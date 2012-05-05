#!/usr/bin/env python3

"""
    A file encryption utility for decentralized access control lists.

    Copyright (C) 2011
      Scott Bezek, Wissam Jarjoui, Di Liu, Michael Morris-Pearce

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

from bblib import *

import argparse
import fnmatch
import getpass
import os
import pickle
import shlex
import shutil
import subprocess
import sys

VERSION = """
0.2
"""
AUTHORS = """
bitbox is the collaborative work of:
  Scott Bezek
  Wissam Jarjoui
  Di Liu
  Michael Morris-Pearce
"""
MAINTAINERS = """
bitbox is presently maintained by:
  Michael Morris-Pearce
"""
DESCRIPTION = """
bitbox is a program to enable decentralized cryptographic access control lists
(ACLs). It uses pairing-based encryption on keys to enforce ACL access to the
ciphertext. Only a user possessing a secret 'token' listed in the ACL can access
the key. The ACL therefore is capable of operating independent of any one
filesystem or user authentication realm. Modifying the key does not necessitate
modifying tokens, so the system is suitable for decentralized & offline usage.

This program will generate tokens, manage ACL settings for files, and encrypt/
decrypt with AES-256 (you will need to install openSSL and the Tar archiver).

Additional information can be found at <http://bitbox.mit.edu>.
"""
COPYRIGHT = """
Copyright (C) 2011 the authors.
"""
LICENSE = """
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
"""
DEPENDS = """
libpbc
python3
python3-dev
openssl
tar
"""
TOKEN_WARNING = """

*** WARNING ***
Exported tokens should only be shared with their intended party (use a trusted
public key or deliver physically). All copies of exported tokens should be
deleted by you and the recipient after successful exchange and import.

"""
HELP_CMD = """
Run \'bitbox COMMAND -h\' for specific command usage.
"""

HELP_CONFIG_ROOT = HELP_CRYPTOSYSTEM = HELP_CONTEXT = HELP_MAX_USERS = HELP_PRIME_STRENGTH = HELP_GEN = HELP_TAGS = HELP_EXPORT = HELP_IMPORT = HELP_FILES = HELP_ACL = HELP_OUTPUT = HELP_ENCRYPT = HELP_DECRYPT = HELP_EXCLUDE = ""

DEFAULT_SETTINGS = {\
    "context":"local", \
    "security":100, \
    "strength":256, \
    "root":os.path.expanduser("~/.bitbox")}
settings = {\
    "root":os.path.expanduser("~/.bitbox")}
cryptosystem = None
temp_password = None
END_BLOCK = "-----END BLOCK-----"

# Read local configuration
def open_profile():
    global settings

    # Make new directory if path doesn't exist
    if not os.path.exists(settings['root']):
        os.mkdir(settings['root'])

    settingsPath = os.path.join(settings['root'], ".settings")

    # Write default settings to a new profile
    if not os.path.exists(settingsPath):
        f = open(settingsPath, 'wb')
        pickle.dump(DEFAULT_SETTINGS, f)
        f.close()

    # Load a preexisting profile
    f = open(settingsPath, 'rb')
    settings = pickle.load(f)
    f.close()
    
# Write local configuration
def close_profile():
    settingsPath = os.path.join(settings['root'], ".settings")
    f = open(settingsPath, 'wb')
    pickle.dump(settings, f)
    f.close()

# List all cryptographic contexts in the configuration
# @return a list of context names
def context_list():
    files = os.listdir(settings['root'])
    contexts = [f for f in files \
        if os.path.isdir(os.path.join(settings['root'],f))]
    return contexts

# Add a new cryptographic context
# @return a new cryptosystem for the current context
def create_context(name):
    contextPath = os.path.join(settings['root'], name)
    os.mkdir(contextPath)
    print("Building new %i-bit cryptosystem for %i maximum uids ..." % \
        (settings['strength'], settings['security']))
    c = Cryptosystem.new(settings['security'], settings['strength'])
    c.createTag("me")
    return c

# Load and initialize the current cryptosystem context
# @return a cryptosystem for a preexisting context
def open_context():
    global temp_password
 
    print("(Using context: '" + str(settings["context"]) + "')\n")
    contextPath = os.path.join(settings['root'], settings["context"])

    # Load the cryptosystem
    f = open(os.path.join(contextPath, "crypt"), 'r')
    str_crypt = f.read()
    f.close()
    # Initialize the cryptosystem
    c = Cryptosystem.fromPairingFileAndString(os.path.join(contextPath, \
        "pairing"), str_crypt)
    
    # Load the encrypted secrets from local configuration
    if os.path.exists(os.path.join(contextPath, "secrets")):
        failed = 0
        while failed < 3:
            temp_password = getpass.getpass("Enter context password: ")
            ret_val, secrets = str_decrypt_aes(os.path.join(contextPath, \
                "secrets"), temp_password)
            if ret_val == 0:
                break;
            failed += 1
            print("Sorry, please try again.")
        if failed >= 3:
            print("Too many failed password attempts")
            exit()
        c.loadSecrets(secrets)

    return c

# Write changes to the current crytosystem context
def close_context(context, save=True):
    global temp_password

    # Save the cryptosystem
    if save:
        contextPath = os.path.join(settings['root'], settings["context"])
        context.exportPairingParams(os.path.join(contextPath, \
            "pairing"))
        str_crypt = context.exportCryptoBasics()
        f = open(os.path.join(contextPath, "crypt"), 'w')
        f.write(str_crypt)
        f.close()
        str_sk = context.getSecrets()

        # The user must enter a password
        if not temp_password:
            print("Please create a password to secure context '" \
                + settings["context"] + "':\n")
            while True:
                pw1 = getpass.getpass("Create context password: ")
                pw2 = getpass.getpass("Confirm context password: ")
                if (pw1 == pw2):
                    break;
            temp_password = pw1

        # Encrypt the tokens and secret key
        str_encrypt_aes(str_sk, os.path.join(contextPath, "secrets"), \
            temp_password)

# Add/remove/list cryptosystem contexts by name
def handle_context(name = None):
    if (name is not None):
        settings["context"] = name 
        if not os.path.exists(os.path.join(settings['root'], name)):
            cs = create_context(name)
            print('Created new context "' + str(name) + '"')
            close_context(cs)
        print('Using context "' + settings["context"] + '"')
        
    # List all contexts and indicate current
    if (name is None):
        print("Available contexts:")
        contexts = context_list()
        contexts = [f+"*" if f==settings["context"] else f for f in contexts]
        print("\n".join(contexts))

# Add tokens
def handle_generate(create_tags = []):
    if (create_tags is None):
        print("You must provide unique names for new tokens.")
        return
    
    # Load the cryptosystem
    cs = open_context()

    # Add these tokens
    for name in create_tags:
        if name in cs.tags:
            print("Token already exists! (" + str(name) + ")")
        else:
            cs.createTag(name)
            print("Created new token '" + str(name) + "'")
    
    # Save the cryptosystem
    close_context(cs)

# Export tokens
def handle_export(export_tags = []):
    if (export_tags is None):
        print("You must provide names of existing tokens to export.")
        return
    
    # Load the cryptosystem
    cs = open_context()  

    # Create unencrypted exports of tokens for a recipient
    for name in export_tags:
        if name in cs.tags:
            f = open("rawToken", 'w')
            f.write(str(cs.tags[name][0]))
            f.close()

            shutil.copy2(os.path.join(settings['root'], \
                settings["context"], "pairing"), "pairing")
            shutil.copy2(os.path.join(settings['root'], \
                settings["context"], "crypt"), "crypt")
            
            resultFile = name + "_" + settings["context"] + ".token"
            tokenFiles = ["rawToken",  "pairing", "crypt"]

            if not tarball(resultFile, tokenFiles):
                print("Failed to export token '" + str(name) + "'!")
            else:
                print("Exported token '" + str(name) + "' --> " + resultFile)

            os.remove("rawToken")
            os.remove("pairing")
            os.remove("crypt")
        else:
            print("Unknown token: " + str(name))

    print(TOKEN_WARNING)

    # Close the crytosystem
    close_context(cs)

# Import a token
def handle_import(import_files):
    if (import_files is None or len(import_files) == 0):
        print("You must provide token files to import.")
        return

    # Use context argument or create a new context, but do not add to an
    # existing context (that would be a special case).
    import_context = settings['context']
    while import_context in context_list():
        import_context = input("Creating new context for imported token. Please name it: ")
    
    for import_file in import_files:
        if not untarball(import_file):
            print("Failed to import token file.")
            return
        
        settings["context"] = import_context
        contextPath = os.path.join(settings['root'], import_context)
        os.mkdir(contextPath)

        shutil.move("pairing", contextPath)
        shutil.move("crypt", contextPath)

        f = open("rawToken", 'r')
        rawToken = f.read()
        f.close()
        os.remove("rawToken")

    temp_password = None  #reset the temporarily stored password

    cs = open_context()
    cs.tags["me"] = (Token.fromStr(cs.pairing,rawToken), None)
    close_context(cs)

# Add/remove/list tokens in current context by tag
def handle_list_tokens():
    cs = open_context()
    print("Available tokens:")
    print("\n".join(list(cs.tags.keys())))
    close_context(cs, save=False)
    return

# Encrypt all listed filenames readable by the listed tags
def handle_encrypt(filenames, tags, exclude = False):
    if (tags is None):
        print('ABORT: You did not specify any tokens!')
        return
    cs = open_context()

    # Give the file owner read permission by default
    if (not exclude):
        tags.append("me")

    # Remove duplicates
    tags = list(set(tags))

    # Encrypt all listed filenames
    print('Encrypting for %s:' % str(tags))
    for filename in filenames:
        print(filename)

        # Encrypt the key with SSW,  encrypt the file with AES
        k = encrypt_aes(filename, filename + '.aes', generate_aes_key())
        if k is None:
            continue
        k_int = int(k, 16)
        ciphers = cs.encryptWithTags(tags, k_int)

        # Write the ciphertext
        f = open(filename + ".key", 'w')
        scipher = ""
        for c in ciphers:
            scipher += str(c)
            scipher += END_BLOCK
            scipher += "\n"
        f.write(scipher)
        f.close()

        # Archive the file and key together with the tar utility
        if not tarball(filename+'.bb', [filename+'.aes', filename+'.key']):
            print('Failed to archive: ' + filename)
            continue
        
        # Delete the temporary files
        os.remove(filename+'.aes')
        os.remove(filename+'.key')

    # Write changes to home directory
    close_context(cs, save=False)

# Take a tarball, dearchive & decrypt (key, file)
def handle_decrypt(tarballnames):
    cs = open_context()
    
    for tarballname in tarballnames:
        # De-archive the (file, key)
        if not untarball(tarballname):
            print('Failed to dearchive: ' + tarballname)
            return

        # Find the ciphertext and encrypted key
        aesFile = None
        keyfile = None
        for f in os.listdir('.'):
            if fnmatch.fnmatch(f, '*.key'):
                keyfile = f
            if fnmatch.fnmatch(f, '*.aes'):
                aesFile = f

        # Fail if either file is missing
        if aesFile is None or keyfile is None:
            print('Failed to load files!')
            return

        # Read the key blocks
        f = open(keyfile, 'r')
        e1 = f.read().split(END_BLOCK + "\n")
        e1.pop() #remove excess empty block
        e1 = [Ciphertext.fromStr(cs.pairing, x) for x in e1]
        f.close()

        # Decrypt the key & message
        k = cs.decryptWithTag("me", e1)
        if k:
            k = hex(k)[2:] #get rid of the '0x' prefix
            decrypt_aes(aesFile, aesFile[:-4], k)
            print("Decrypted " + aesFile[:-4] + "!")
        else:
            print("Couldn't decrypt file")

        # Cleanup
        os.remove(aesFile)
        os.remove(keyfile)

# Generate a 256-bit key for AES.
def generate_aes_key():
    k = 0
    for b in os.urandom(32):
        k |= b
        k = k << 4
    k = k >> 4
    return str(k)

# Encrypt a file with AES.
def encrypt_aes(infile, outfile, k):
    try:
        f = open(infile)
        f.close()
        p = subprocess.Popen(shlex.split('openssl enc -aes-256-cbc -in ' \
            + infile + ' -out ' + outfile + ' -pass stdin'), \
            stdin = subprocess.PIPE)
        outstr = k + "\n"
        out, err = p.communicate(bytearray(outstr.encode('utf8')))
        return k
    except:
        print('SKIPPING ' + infile + ': could not open!')
        return None

# Decrypt a file with AES
def decrypt_aes(infile, outfile, k):
    try:
        f = open(infile)
        f.close()
        p = subprocess.Popen(shlex.split('openssl enc -d -aes-256-cbc -in ' \
            + infile + ' -out ' + outfile + ' -pass stdin'), \
            stdin = subprocess.PIPE)
        outstr = k + "\n"
        out, err = p.communicate(bytearray(outstr.encode('utf8')))
        return k
    except:
        print('SKIPPING ' + infile + ': could not open!')
        return None

# Encrypt a string with AES given a key.
def str_encrypt_aes(string, outfile, k):
    try:
        p = subprocess.Popen(shlex.split('openssl enc -aes-256-cbc -out ' \
            + outfile + ' -pass stdin'), \
            stdin = subprocess.PIPE)
        outstr = k + "\n" + string
        out, err = p.communicate(bytearray(outstr.encode('utf8')))
        return p.returncode
    except:
        print('An error occurred encrypting ' + outfile)
        return None

# Decrypt a file to a string with AES given a key.
def str_decrypt_aes(infile, k):
    try:
        p = subprocess.Popen(shlex.split('openssl enc -d -aes-256-cbc -in ' \
            + infile + ' -pass stdin'), \
            stdin = subprocess.PIPE, \
            stdout = subprocess.PIPE)
        outstr = k + "\n"
        out, err = p.communicate(bytearray(outstr.encode('utf8')))
        return p.returncode, str(out)
    except:
        print('An error occurred decrypting ' + infile)
        return 100, None

# Make a tar archive with compression
def tarball(outname, files):
    try:
        p = subprocess.Popen(shlex.split('tar -cz --file ' \
            + outname + ' ' + " ".join(files)))
        p.communicate()
        return p.returncode == 0
    except:
        return False

# Extract a tar archive
def untarball(filename):
    try:
        print(filename)
        p = subprocess.Popen(shlex.split('tar -xz --file ' + filename))
        p.communicate()
        return p.returncode == 0
    except:
        return False

# Setup parser
def setup_parser():
    p = argparse.ArgumentParser(description = DESCRIPTION)
    
    # Take a command argument {a,d,e,g,i,s,x}
    subps = p.add_subparsers(dest = 'cmd', \
        help = HELP_CMD)
    
    # Specify which directory to use for configuration files
    p.add_argument('--config-dir', dest='config', nargs='?', \
        help = HELP_CONFIG_ROOT)
    
    # Setup/switch the context
    p_setup = subps.add_parser('s', \
        help = HELP_CRYPTOSYSTEM)
    p_setup.add_argument(dest='name', nargs='?', \
        help = HELP_CONTEXT)
    p_setup.add_argument('--max-users', dest='users', nargs='?', \
        help = HELP_MAX_USERS)
    p_setup.add_argument('--prime-strength', dest='strength', nargs='?', \
        help = HELP_PRIME_STRENGTH)
    
    # Generate tokens
    p_gen = subps.add_parser('g', \
        help = HELP_GEN)
    p_gen.add_argument(dest='tags', nargs='+', \
        help = HELP_TAGS)
    p_gen.add_argument('--context', dest='name', nargs='*', \
        help = HELP_CONTEXT)
    
    # Export tokens
    p_export = subps.add_parser('x', \
        help = HELP_EXPORT)
    p_export.add_argument(dest='tags', nargs='+', \
        help = HELP_TAGS)
    p_export.add_argument('--context', dest='name', nargs='*', \
        help = HELP_CONTEXT)
    
    # Import tokens
    p_import = subps.add_parser('i', \
        help = HELP_IMPORT)
    p_import.add_argument(dest = 'files', nargs=1, \
        help = HELP_FILES)
    p_import.add_argument('--context', dest='name', nargs='*', \
        help = HELP_CONTEXT)
    
    # ACL modification
    p_acl = subps.add_parser('a', \
        help = HELP_ACL)
    p_acl.add_argument(dest = 'files', nargs='*', \
        help = HELP_FILES)
    p_acl.add_argument('--output', dest='output', nargs='?', \
        help = HELP_OUTPUT)
    p_acl.add_argument('--tokens', dest='tags', nargs='+', \
        help = HELP_TAGS)
    p_acl.add_argument('--context', dest='name', nargs='*', \
        help = HELP_CONTEXT)
    
    # Encrypt
    p_encrypt = subps.add_parser('e', \
        help = HELP_ENCRYPT)
    p_encrypt.add_argument(dest = 'files', nargs='+', \
        help = HELP_FILES)
    p_encrypt.add_argument('--output', dest='output', nargs='?', \
        help = HELP_OUTPUT)
    p_encrypt.add_argument('--tokens', dest='tags', nargs='+', \
        help = HELP_TAGS)
    p_encrypt.add_argument('--context', dest='name', nargs='*', \
        help = HELP_CONTEXT)
    p_encrypt.add_argument('--exclude-me', dest='exclude', \
        action='store_true', help = HELP_EXCLUDE)
    
    # Decrypt
    p_decrypt = subps.add_parser('d', \
        help = HELP_DECRYPT)
    p_decrypt.add_argument(dest = 'files', nargs='+', \
        help = HELP_FILES)
    p_decrypt.add_argument('--output', dest='output', nargs='?', \
        help = HELP_OUTPUT)
    p_decrypt.add_argument('--tokens', dest='tags', nargs='+', \
        help = HELP_TAGS)
    p_decrypt.add_argument('--context', dest='name', nargs='*', \
        help = HELP_CONTEXT)

    return p

if __name__ == "__main__":
    p = setup_parser()
    args = vars(p.parse_args(sys.argv[1:]))

    if (args['config'] is not None):
        settings['root'] = args['config']
    else:
        settings['root'] = DEFAULT_SETTINGS['root']

    # Load user's settings from config directory, .setting file
    open_profile()

    #print("Using config found in " + settings['root'])

    if (args['name'] is not None):
        settings['context'] = args['name']

    # Setup a new context or switch the current context.
    if (args['cmd'] == 's'):
        if (args['users'] is not None):
            settings['security'] = int(args['users'])
        else:
            settings['security'] = DEFAULT_SETTINGS['security']
        if (args['strength'] is not None):
            settings['strength'] = int(args['strength'])
        else:
            settings['strength'] = DEFAULT_SETTINGS['strength']
        handle_context(\
            args['name'])

    # Generate a new token for this context.
    elif (args['cmd'] == 'g'):
        handle_generate(args['tags'])

    # Export a token.
    elif (args['cmd'] == 'x'):
        handle_export(args['tags'])

    # Import a token.
    elif (args['cmd'] == 'i'):
        handle_import(args['files'])

    # TODO: Change the ACL on a file.
    #elif (args['cmd'] == 'a'):
        #handle_acl(args
        
    # Encrypt a file.
    elif (args['cmd'] == 'e'):
        handle_encrypt(args['files'], args['tags'], \
            exclude = args['exclude'])
        
    # Decrypt a file.
    elif (args['cmd'] == 'd'):
        handle_decrypt(args['files'])
    else:
        print('Not a valid command.')
    
    # Save any config changes to the .setting file
    close_profile()
