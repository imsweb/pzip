import argparse
import getpass
import io
import os
import secrets
import sys

import tqdm

from .base import DEFAULT_ITERATIONS, InvalidFile, PZip
from .reader import PZipReader
from .writer import PZipWriter


def log(msg, *args):
    print(msg.format(*args), file=sys.stderr, flush=True)


def die(msg, *args, code=1):
    log(msg, *args)
    sys.exit(code)


def copy(infile, outfile, progress=None):
    """
    Copies infile to outfile in chunks, optionally updating a progress bar. Closes infile and outfile upon completion,
    if they are not interactive.
    """
    block_size = getattr(outfile, "block_size", PZip.DEFAULT_BLOCK_SIZE)
    while True:
        if hasattr(infile, "read_block"):
            chunk = infile.read_block()
        else:
            chunk = infile.read(block_size)
        if not chunk:
            break
        if hasattr(outfile, "write_block"):
            outfile.write_block(chunk)
        else:
            outfile.write(chunk)
        if progress:
            progress.update(len(chunk))
    if progress:
        progress.close()
    if not infile.isatty() and not isinstance(infile, io.BytesIO):
        infile.close()
    if not outfile.isatty() and not isinstance(outfile, io.BytesIO):
        outfile.close()


def get_files(filename, mode, key, options):
    """
    Given an input filename (possibly None for STDIN), a mode (ENCRYPT or DECRYPT), a key, and the command line
    options, this method will return a tuple:

        (infile, outfile, total)

    Where infile and outfile will be open and ready to read/write, and total is the number of expected bytes to read
    from infile.
    """
    infile = None
    outfile = None
    total = None
    if options.stdout:
        outfile = sys.stdout.buffer
    elif options.output:
        if not options.force and os.path.exists(options.output):
            die("%s: output file exists", options.output)
        outfile = open(options.output, "wb")
    if mode == "wb":
        if filename:
            infile = open(filename, "rb")
            # If not already specified, set output file to <filename>.pz.
            if not outfile:
                if not options.force and os.path.exists(filename + ".pz"):
                    die("%s: output file exists", filename + ".pz")
                outfile = open(filename + ".pz", "wb")
            # Progress total will be the size of the input file when encrypting.
            total = os.path.getsize(filename)
        else:
            infile = sys.stdin.buffer
            # If using STDIN and no output was specified, use STDOUT.
            if not outfile:
                outfile = sys.stdout.buffer
        # Wrap the output file in a PZip object.
        outfile = PZipWriter(outfile, key, compress=not options.nozip)
    elif mode == "rb":
        fileobj = open(filename, mode) if filename else sys.stdin.buffer
        infile = PZipReader(fileobj, key, decompress=not options.extract)
        # PZip's read will return uncompressed data by default, so this should be the uncompressed plaintext size.
        total = infile.plaintext_size()
        if not outfile:
            if filename:
                # If an output wasn't specified, and we have a filename, strip off the last suffix (.pz).
                new_filename = filename.rsplit(".", 1)[0]
                if options.extract and infile.compression.value != 0:
                    # Special case for when we're just extracting the compressed data, add a .gz suffix.
                    # TODO: get this suffix from the PZip object, in case we add compression options.
                    new_filename += ".gz"
                    # Set the progress total to the (compressed) ciphertext size, since we aren't decompressing.
                    total = infile.ciphertext_size()
                if not options.force and os.path.exists(new_filename):
                    die("%s: output file exists", new_filename)
                outfile = open(new_filename, "wb")
            else:
                # Using STDIN and no output was specified, just dump to STDOUT.
                outfile = sys.stdout.buffer
    return infile, outfile, total


def print_info(filename, show_errors=False):
    try:
        fileobj = sys.stdin.buffer if filename == "-" else open(filename, "rb")
        with PZipReader(fileobj) as f:
            info = "{}: PZip version {}".format(filename, f.version)
            for field in ("algorithm", "kdf", "compression"):
                v = getattr(f, field)
                if v.value:
                    info += " | " + v.name.replace("_", "-")
            print(info)
    except FileNotFoundError:
        if show_errors:
            log("{}: file not found", filename)
    except IsADirectoryError:
        if show_errors:
            log("{}: is a directory", filename)
    except InvalidFile as e:
        if show_errors:
            log("{}: {}", filename, str(e))


def main(*args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-z", "--compress", action="store_true", default=False, help="force compression")
    parser.add_argument("-d", "--decompress", action="store_true", default=False, help="force decompression")
    parser.add_argument("-k", "--keep", action="store_true", default=False, help="keep input files")
    parser.add_argument("-c", "--stdout", action="store_true", default=False, help="write to stdout (implies -kq)")
    parser.add_argument("-f", "--force", action="store_true", default=False, help="overwrite existing output files")
    parser.add_argument("-a", "--auto", action="store_true", help="automatically generate and output a key")
    parser.add_argument("-e", "--key", help="encrypt/decrypt using key file")
    parser.add_argument("-p", "--password", help="encrypt/decrypt using password")
    parser.add_argument("-i", "--iterations", type=int, default=DEFAULT_ITERATIONS, help="number of PBKDF2 iterations")
    parser.add_argument("-o", "--output", help="specify outfile file name")
    parser.add_argument("-n", "--nozip", action="store_true", default=False, help="encrypt only, no compression")
    parser.add_argument("-x", "--extract", action="store_true", default=False, help="extract only, no decompression")
    parser.add_argument("-q", "--quiet", action="store_true", default=False, help="no output")
    parser.add_argument(
        "-l", "--list", action="store_true", default=False, help="print information about the specified files"
    )
    parser.add_argument("files", metavar="file", nargs="*", help="files to encrypt or decrypt")
    options = parser.parse_args(args=args or None)
    if options.list:
        if not options.files:
            die("no files specified")
        for filename in options.files:
            print_info(filename, show_errors=not options.quiet)
        return
    if options.compress and options.decompress:
        die("cannot specify -z and -d together")
    files = []
    mode = None
    if options.compress:
        mode = "wb"
    elif options.decompress:
        mode = "rb"
    for filename in options.files:
        if filename == "-":
            continue
        elif os.path.exists(filename):
            with open(filename, "rb") as f:
                file_mode = "rb" if f.read(len(PZip.MAGIC)) == PZip.MAGIC else "wb"
            if mode is None:
                mode = file_mode
            elif mode != file_mode:
                die("%s: mode conflict", filename)
            files.append(filename)
        else:
            log("{}: no such file", filename)
    if mode is None:
        die("unable to determine mode; specify -z or -d")
    if not files:
        # Default to using stdin if no files were specified.
        files = [None]
    if options.stdout:
        if len(files) > 1:
            die("can only output a single file to stdout")
        options.keep = True
        options.quiet = True
    if options.key:
        with open(options.key, "rb") as f:
            key = f.read()
        if options.password:
            log("-p ignored, using key file {}", options.key)
    elif options.password:
        key = options.password
        if options.auto:
            log("-a ignored, using password")
    elif options.auto:
        key = secrets.token_urlsafe(16)
        # Not strictly a problem, but make it easy to use as an argument to -p.
        while key.startswith("-"):
            key = secrets.token_urlsafe(16)
        log("encrypting with password: {}", key)
    else:
        key = getpass.getpass("Password: ")
        if mode == "wb":
            verify = getpass.getpass("Verify: ")
            if verify != key:
                die("passwords did not match")
    for filename in files:
        infile, outfile, total = get_files(filename, mode, key, options)
        progress = (
            tqdm.tqdm(desc=filename, total=total, unit="B", unit_scale=True, unit_divisor=1024)
            if filename and total and not options.quiet
            else None
        )
        copy(infile, outfile, progress=progress)
        if filename and not options.keep:
            os.remove(filename)


if __name__ == "__main__":
    main()
