#!/usr/bin/env python3
#
# This script creates a local mirror for third-party packages used
# in Contrail builds.
#
# Usage: populate_cache.py target_directory/ packages.xml

import logging
import argparse
import os
import hashlib
import shutil
import sys
from urllib.request import urlopen
from urllib3.exceptions import SubjectAltNameWarning
import warnings
import ssl
import xml.etree.ElementTree


LOG = logging.getLogger("populate_cache")
LOG.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

LOG.addHandler(ch)

warnings.filterwarnings('ignore', category=SubjectAltNameWarning)
warnings.filterwarnings('ignore', ".*SNIMissingWarning.*")
warnings.filterwarnings('ignore', ".*InsecurePlatformWarning.*")
warnings.filterwarnings('ignore', ".*SubjectAltNameWarning.*")


def get_package_details(element):
    md5sum = element.find('md5').text
    # can be array
    canonical_url = element.find('urls').findall("url[@canonical='true']")
    cache_url = next(url.text for url in element.find('urls') if "{{ site_mirror }}" in url.text)
    filename = cache_url.replace("{{ site_mirror }}/", "")

    return (canonical_url, filename, md5sum)


def cached_file_exists(dest, filename, md5sum):
    parent_dir = os.path.join(dest, filename[0])
    local_path = os.path.join(parent_dir, filename)

    if not os.path.exists(local_path):
        LOG.info("File %s missing, will download", filename)
        return False

    with open(local_path, 'rb') as fh:
        calculated_md5 = hashlib.md5(fh.read()).hexdigest()
        if calculated_md5 != md5sum:
            LOG.warn("File %s found, but checksum mismatch "
                     "(found: '%s' expected: '%s')",
                     filename, calculated_md5, md5sum)
            return False

    LOG.info("File %s found, checksum matches", filename)
    return True


def download_package(canonical_url, dest, filename, md5sum):
    local_path = os.path.join(dest, filename)
    parent_dir = os.path.dirname(local_path)
    temp_path = local_path + '.tmp'

    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    context = ssl._create_unverified_context()
    req = urlopen(canonical_url, context=context)
    chunk = 16 * 1024
    with open(temp_path, 'wb') as fh:
        shutil.copyfileobj(req, fh, chunk)

    with open(temp_path, 'rb') as fh:
        calculated_md5 = hashlib.md5(fh.read()).hexdigest()
        if calculated_md5 != md5sum:
            LOG.error("File %s checksum error"
                      "(found: '%s' expected: '%s')",
                      filename, calculated_md5, md5sum)
            return False

    LOG.info("File %s downloaded, checksum matches", filename)

    if os.path.exists(local_path):
        os.unlink(local_path)
    os.rename(temp_path, local_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", nargs=1)
    parser.add_argument("file", nargs=1)
    args = parser.parse_args(sys.argv[1:])

    dest = args.destination[0]
    LOG.info("INFO: save artefacts to %s", dest)

    tree = xml.etree.ElementTree.parse(args.file[0])
    for item in tree.getroot():
        if item.tag != 'package':
            continue
        canonical_url, filename, md5sum = get_package_details(item)
        if cached_file_exists(dest, filename, md5sum):
            continue
        for url in canonical_url:
            try:
                if download_package(url.text, dest, filename, md5sum):
                    break
            except Exception as e:
                LOG.error("Exception during download %s: %s", url.text, e)
        else:
            LOG.error("ERROR!!! File %s was not downloaded", filename)


if __name__ == "__main__":
    main()
