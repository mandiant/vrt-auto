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
import requests.exceptions

from vrt_auto.candidates import AbstractActionCandidate
from vrt_auto.candidates import AbstractDNSActionCandidate
from vrt_auto.candidates import AbstractEmailAttachmentActionCandidate
from vrt_auto.candidates import AbstractEmailNoAttachmentActionCandidate
from vrt_auto.candidates import AbstractFileCandidate
from vrt_auto.candidates import AbstractMFTActionCandidate
from vrt_auto.candidates import AbstractProtectedTheaterFileActionCandidate
from vrt_auto.utils import find_file_on_director
from vrt_auto.utils import VRTAutoClientManager
from vrt_sdk import FileExistsOnDirectorError
from vrt_sdk import FileRestrictionsEnum
from vrt_sdk import PartialAction
import vrt_sdk.exceptions


def apply_all_candidate_tags(cm: VRTAutoClientManager,
                             candidate: AbstractActionCandidate,
                             action_creation_response: PartialAction) -> None:
  """Apply all tags defined by a Candidate to the created Action.

  Covers the following tag types:
   - user
   - user_run_as
   - user_src_destination
   - user_os
   - user_control
   - user_mitigation
   - user_nist_control

  Args:
    cm: VRTAutoClientManager
    candidate: The Candidate used to create the given Action
    action_creation_response: The Action created from the Candidate
  """
  for item in candidate.user_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user")
  for item in candidate.user_run_as_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user_run_as")
  for item in candidate.user_src_dst_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user_src_destination")
  for item in candidate.user_os_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user_os")
  for item in candidate.user_control_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user_control")
  for item in candidate.user_mitre_mitigation_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user_mitre_mitigation")
  for item in candidate.user_nist_control_tags:
    cm.director_client.add_tag_to_action(action_creation_response, item,
                                         "user_nist_control")


def auto_file(cm: VRTAutoClientManager,
              candidate: AbstractFileCandidate) -> int | None:
  """Create a file per Candidate specifications.

  Args:
    cm: VRTAutoClientManager specifying the Director to target
    candidate: The file Candidate

  Returns:
    An integer representing the file ID on the director, or None if the file
      already exists
  """

  try:
    fileid = cm.director_client.upload_file(
        candidate.file_bytes,
        candidate.file_name,
        FileRestrictionsEnum.RESTRICTED_MALICIOUS,
        candidate.file_description,
        candidate.operating_system)
  except FileExistsOnDirectorError:
    return None

  for item in candidate.user_tags:
    cm.director_client.add_tag_to_file(fileid, item)

  return fileid


def auto_mft(cm: VRTAutoClientManager,
             candidate: AbstractMFTActionCandidate) -> PartialAction:
  """Create an MFT Action per Candidate specifications.

  Args:
    cm: VRTAutoClientManager specifying the Director to target
    candidate: The MFT Candidate

  Returns:
    A PartialAction object representing the created Action
  Raises:
    FileNotFoundError: If we have a file id, but cannot find the file
    ValueError: If Candidate is missing a file_target
  """

  if not candidate.file_target:
    raise ValueError(
        "MFT Actions require a candidate with the file_target attribute. See "
        "AbstractMFTActionCandidate.")

  file_id = auto_file(cm, candidate.file_target)

  if not file_id:
    file_id = find_file_on_director(cm.director_client,
                                    candidate.file_target.file_hash)

  if not file_id:
    raise FileNotFoundError(
        "File is allegedly already present on director, but could not be found")

  # Create action
  try:
    response = cm.director_client.create_file_transfer_action(
        candidate.action_title,
        candidate.action_description,
        file_id=file_id,
        os_value=candidate.file_target.operating_system)
  except requests.exceptions.HTTPError as e:
    if "\"name\":[\"must be unique\"" in e.response.text:
      raise vrt_sdk.exceptions.ActionCreationError(
          "An Action with this name already exists") from e
    else:
      raise e

  # Tag action
  apply_all_candidate_tags(cm, candidate, response)

  print(response)
  return response


def auto_dns(cm: VRTAutoClientManager,
             candidate: AbstractDNSActionCandidate) -> PartialAction:
  """Create a DNS Action per Candidate specifications.

  Args:
    cm: VRTAutoClientManager specifying the Director to target
    candidate: The DNS Candidate

  Returns:
    A PartialAction object representing the created Action
  Raises:
    ValueError: If Candidate is missing a domain
  """

  if not candidate.domain:
    raise ValueError(
        "DNS Actions require a candidate with the domain attribute. "
        "See AbstractDNSActionCandidate.")

  # Create action
  try:
    response = cm.director_client.create_dns_action(candidate.action_title,
                                                    candidate.action_description,
                                                    candidate.domain)
  except requests.exceptions.HTTPError as e:
    if "\"name\":[\"must be unique\"" in e.response.text:
      raise vrt_sdk.exceptions.ActionCreationError(
          "An Action with this name already exists") from e
    else:
      raise e

  # Tag action
  apply_all_candidate_tags(cm, candidate, response)

  print(response)
  return response


def auto_email_link(cm: VRTAutoClientManager,
                    candidate: AbstractEmailNoAttachmentActionCandidate
                    ) -> PartialAction:
  """Create an Email Action with no attachment per Candidate specifications.

  Args:
    cm: VRTAutoClientManager specifying the Director to target
    candidate: The Email (No Attachment) Candidate

  Returns:
    A PartialAction object representing the created Action

  Raises:
    ValueError: If Candidate is missing a body
  """

  if not candidate.body:
    raise ValueError(
        "Phishing Link Actions require a candidate with the body attribute."
        " See AbstractEmailLinkActionCandidate.")

  # Create action
  try:
    response = cm.director_client.create_email_action(
        candidate.action_title,
        candidate.action_description,
        candidate.body,
        "TEST EMAIL")
  except requests.exceptions.HTTPError as e:
    if "\"name\":[\"must be unique\"" in e.response.text:
      raise vrt_sdk.exceptions.ActionCreationError(
          "An Action with this name already exists") from e
    else:
      raise e

  # Tag action
  apply_all_candidate_tags(cm, candidate, response)

  print(response)
  return response


def auto_email_attachment(cm: VRTAutoClientManager,
                          candidate: AbstractEmailAttachmentActionCandidate
                          ) -> PartialAction:
  """Create an Email Action with an attachment per Candidate specifications.

  Args:
    cm: VRTAutoClientManager specifying the Director to target
    candidate: The Email (w/Attachment) Candidate

  Returns:
    A PartialAction object representing the created Action

  Raises:
    FileNotFoundError: If we have a file id, but cannot find the file
    ValueError: If Candidate is missing a file_target
  """

  if not candidate.file_target:
    raise ValueError(
        "Phishing Attachment Actions require a candidate with the file_target "
        "attribute. See AbstractEmailAttachmentActionCandidate.")

  file_id = auto_file(cm, candidate.file_target)

  if not file_id:
    file_id = find_file_on_director(cm.director_client,
                                    candidate.file_target.file_hash)

  if not file_id:
    raise FileNotFoundError(
        "File is allegedly already present on director, but could not be found")

  # Create action
  try:
    response = cm.director_client.create_email_action(
        candidate.action_title,
        candidate.action_description,
        candidate.body,
        "TEST EMAIL",
        file_attachment=file_id)
  except requests.exceptions.HTTPError as e:
    if "\"name\":[\"must be unique\"" in e.response.text:
      raise vrt_sdk.exceptions.ActionCreationError(
          "An Action with this name already exists") from e
    else:
      raise e

  # Tag action
  apply_all_candidate_tags(cm, candidate, response)

  print(response)
  return response


def auto_protected_theater_from_file(
    cm: VRTAutoClientManager,
    candidate: AbstractProtectedTheaterFileActionCandidate) -> PartialAction:
  """Create a Protected Theater Action per Candidate specifications.

  Args:
    cm: VRTAutoClientManager specifying the Director to target
    candidate: The Protected Theater Candidate

  Returns:
    A PartialAction object representing the created Action

  Raises:
    FileNotFoundError: If we have a file id, but cannot find the file
    ValueError: If Candidate is missing a HostActionFactory or file_target
  """

  # Check if the candidate possesses a factory
  if not candidate.factory:
    raise ValueError(
        "Protected Theater Actions require a HostActionFactory. See "
        "AbstractProtectedTheaterActionCandidate.")

  # Check if the candidate has a file target
  if not candidate.file_target:
    raise ValueError(
        "Protected Theater Actions require a candidate with the file_target "
        "attribute. See AbstractProtectedTheaterActionCandidate.")

  # Attempt to upload the file, obtain file id
  file_id = auto_file(cm, candidate.file_target)
  if not file_id:
    file_id = find_file_on_director(cm.director_client,
                                    candidate.file_target.file_hash)
  if not file_id:
    raise FileNotFoundError(
        "File is allegedly already present on director, but could not be found")

  # Add the file to the candidate's factory
  # It's awkward, but there's really no good way around this
  candidate.factory.add_file(file_id, candidate.action_file_path,
                             candidate.action_file_name)

  # Create action
  try:
    response = cm.director_client.create_host_action(candidate.factory)
  except requests.exceptions.HTTPError as e:
    if "\"name\":[\"must be unique\"" in e.response.text:
      raise vrt_sdk.exceptions.ActionCreationError(
          "An Action with this name already exists") from e
    else:
      raise e

  # Tag action
  apply_all_candidate_tags(cm, candidate, response)

  print(response)
  return response
