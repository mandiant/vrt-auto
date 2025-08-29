"""Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import atexit
import base64
import configparser
import hashlib
import io
import os

from vrt_sdk import Director
import vt


class VRTAutoClientManager:
  """Holds client information for resources needed for content creation.

  Waits to instantiate non-director clients until requested.
  """

  def __init__(self, target_director: Director | str):
    """Init method for VRTAutoClientManager.

    Args:
      target_director: Either a Director object or a string according to VRT
        SDK's ini file specification
    """

    self._native_vt_client = None
    self._native_gti_client = None

    if isinstance(target_director, Director):
      self.director_client = target_director

    elif isinstance(target_director, str):
      try:
        self.vrt_config = configparser.RawConfigParser()
        self.vrt_config.read(os.environ["VRTCONFIG"])
      except KeyError as e:
        print("Cannot find VRTCONFIG environment variable")
        raise e
      self.director_client = Director(target_director)

    else:
      raise TypeError(
          "Expected either a Director object or the name of a director")

    atexit.register(self.close_vt_and_gti_clients)

  @property
  def native_vt_client(self) -> vt.client.Client:
    """VirusTotal Client."""
    if not self._native_vt_client:
      self._load_native_vt_client()
    return self._native_vt_client

  def _load_native_vt_client(self) -> None:
    try:
      self._native_vt_client = vt.Client(self.vrt_config["vt"]["api_key"])
    except Exception as e:  # noqa
      raise e

  @property
  def native_gti_client(self) -> vt.client.Client:
    """Google Threat Intelligence Client."""
    if not self._native_gti_client:
      self._load_native_gti_client()
    return self._native_gti_client

  def _load_native_gti_client(self) -> None:
    try:
      self._native_gti_client = vt.Client(self.vrt_config["gti"]["api_key"],
                                          headers={"x-tool": "VRT_AUTO"})
    except Exception as e:  # noqa
      raise e

  def download_file_from_vt(self, file_hash: str) -> bytes:
    """Download a file from VirusTotal by hash.

    Args:
      file_hash: Hash of the file to download

    Returns:
      The requested file as bytes

    Raises:
      ValueError if hash of the received data does not match the expected hash
    """
    content_buffer = io.BytesIO(b"")
    self.native_vt_client.download_file(file_hash, content_buffer)
    content = content_buffer.getvalue()
    content_buffer.close()

    if not _validate_hash(file_hash, content):
      raise ValueError("Received data does not match hash")

    return content

  def download_file_from_gti(self, file_hash: str) -> bytes:
    """Download a file from Google Threat Intelligence by hash.

    Args:
      file_hash: Hash of the file to download

    Returns:
      The requested file as bytes

    Raises:
      ValueError if hash of the received data does not match the expected hash
    """
    content_buffer = io.BytesIO(b"")
    self.native_gti_client.download_file(file_hash, content_buffer)
    content = content_buffer.getvalue()
    content_buffer.close()

    if not _validate_hash(file_hash, content):
      raise ValueError("Received data does not match hash")

    return content

  def get_file_report_from_vt(self, file_hash: str) -> vt.Object:
    """Obtain a file report from VirusTotal.

    Args:
      file_hash: Hash of the file to retrieve information for

    Returns:
      A VirusTotal object containing data about the file
    """
    return self.native_vt_client.get_object(f"/files/{file_hash}")

  def get_file_report_from_gti(self, file_hash: str) -> vt.Object:
    """Obtain a file report from Google Threat Intelligence.

    Args:
      file_hash: Hash of the file to retrieve information for

    Returns:
      A VirusTotal object containing data about the file,
        including Google Threat Intelligence associations
    """
    return self.native_gti_client.get_object(
        f"/files/{file_hash}?relationships=campaigns,malware_families,"
        f"related_threat_actors,vulnerabilities")

  def get_domain_report_from_vt(self, domain: str) -> vt.Object:
    """Obtain a domain report from VirusTotal.

    Args:
      domain: Domain to retrieve information for

    Returns:
      A VirusTotal object containing data about the domain
    """
    return self.native_vt_client.get_object(f"/domains/{domain}")

  def get_domain_report_from_gti(self, domain: str) -> vt.Object:
    """Obtain a domain report from Google Threat Intelligence.

    Args:
      domain: Domain to retrieve information for

    Returns:
      A VirusTotal object containing data about the domain,
        including Google Threat Intelligence associations
    """
    return self.native_gti_client.get_object(
        f"/domains/{domain}?relationships=campaigns,malware_families,"
        f"related_threat_actors,vulnerabilities")

  def get_url_report_from_vt(self, url: str) -> vt.Object:
    """Obtain a URL report from VirusTotal.

    Args:
      url: URL to retrieve information for

    Returns:
      A VirusTotal object containing data about the url
    """
    url_id = calculate_vt_gti_url_id(url)
    return self.native_vt_client.get_object(f"/urls/{url_id}")

  def get_url_report_from_gti(self, url: str) -> vt.Object:
    """Obtain a URL report from Google Threat Intelligence.

    Args:
      url: Domain to retrieve information for

    Returns:
      A VirusTotal object containing data about the URL,
        including Google Threat Intelligence associations
    """
    url_id = calculate_vt_gti_url_id(url)
    return self.native_gti_client.get_object(
        f"/urls/{url_id}?relationships=campaigns,malware_families,"
        f"related_threat_actors,vulnerabilities")

  def get_tags_from_report_relationships(self, report: vt.Object) -> set[str]:
    """Parse relationships and extract relevant tags from a report for content.

    Only Google Threat Intelligence attributions are accepted.

    Args:
      report: Report object to parse (file, domain, or URL)

    Returns:
      A set of tags (strings) to apply to content
    """

    tags = set()

    rels = report.relationships.data

    if actors := rels["related_threat_actors"].data["data"]:
      for entry in actors:
        response = self.native_gti_client.get_object(
            f"/collections/{entry['id']}")
        if response.origin == "Google Threat Intelligence":
          tags.add(response.name)

    if malware_families := rels["malware_families"].data["data"]:
      for entry in malware_families:
        response = self.native_gti_client.get_object(
            f"/collections/{entry['id']}")
        if response.origin == "Google Threat Intelligence":
          if response.name.isupper():
            tags.add(f"Malware:{response.name}")

    if campaigns := rels["campaigns"].data["data"]:
      for entry in campaigns:
        response = self.native_gti_client.get_object(
            f"/collections/{entry['id']}")
        if response.origin == "Google Threat Intelligence":
          for name in response.alt_names:
            if "CAMP." in name or "GLOBAL." in name:
              tags.add(name)

    if vulns := rels["vulnerabilities"].data["data"]:
      for entry in vulns:
        response = self.native_gti_client.get_object(
            f"/collections/{entry['id']}")
        if response.origin == "Google Threat Intelligence":
          tags.add(response.name)

    return tags

  def close_vt_and_gti_clients(self) -> None:
    """For closing clients at exit."""
    if self._native_vt_client:
      self._native_vt_client.close()
    if self._native_gti_client:
      self._native_gti_client.close()


def calculate_vt_gti_url_id(url: str) -> str:
  """Obtain the VirusTotal/GTI ID for a given URL.

  See https://gtidocs.virustotal.com/reference/urls#url-identifiers

  Args:
    url: URL to generate an ID for.

  Returns:
    A string representing the ID of the URL
  """
  return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


# This is painfully slow since we can't actually search the director for a file.
# We could build a local cache, but then we have to maintain a local cache,
# and I don't trust that such a cache will always be in a good state.
# Unfortunately, this is the only other option.
def find_file_on_director(target_director: Director,
                          file_hash: str) -> int | bool:
  """Function for locating a file on an MSV director.

  This is slow, since MSV doesn't support actually searching for a file by hash.
  This requires us to pull the *entire* file library JSON and iterate through it
  to check if our desired file is there.

  It is feasible that we could build a local cache instead, but I don't consider
  that to be worth the risks involved.

  Args:
    target_director: Director client to query
    file_hash: Hash of the file (MD5, SHA1, SHA256) to search for

  Returns:
    Returns the file id as an integer if the file is found,
      otherwise returns False.
  """
  response = target_director.get_all_files()
  for file in response:
    if file_hash in [file.md5sum, file.sha1sum, file.sha256sum]:
      return file.id
  return False


def _validate_hash(hash_val: str, data: bytes) -> bool:
  """Confirm that the hash of the provided data matches the provided hash.

  Args:
    hash_val: A string representing a hash value (MD5, SHA1, SHA256)
    data: The bytes to validate

  Returns:
    A boolean representing if the provided hash matches the provided data
  """
  if len(hash_val) == 32:
    return hash_val == md5_hash(data)
  elif len(hash_val) == 40:
    return hash_val == sha1_hash(data)
  elif len(hash_val) == 64:
    return hash_val == sha256_hash(data)
  else:
    raise ValueError(f"Hash is of invalid length ({len(hash_val)})")


def md5_hash(data: bytes) -> str:
  """Hash the provided bytes with MD5.

  Args:
    data: The bytes to hash.

  Returns:
    The hash value as a string
  """
  return hashlib.md5(data).hexdigest()


def sha1_hash(data: bytes) -> str:
  """Hash the provided bytes with SHA1.

  Args:
    data: The bytes to hash.

  Returns:
    The hash value as a string
  """
  return hashlib.sha1(data).hexdigest()


def sha256_hash(data: bytes) -> str:
  """Hash the provided bytes with SHA256.

  Args:
    data: The bytes to hash.

  Returns:
    The hash value as a string
  """
  return hashlib.sha256(data).hexdigest()
