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

import base64  # Store live IOCs as B64

from vrt_auto.candidates import GTIVanillaDNSCandidate
from vrt_auto.candidates import GTIVanillaFileCandidate
from vrt_auto.candidates import GTIVanillaMFTCandidate
from vrt_auto.candidates import GTIVanillaPhishingAttachmentCandidate
from vrt_auto.candidates import GTIVanillaPhishingLinkCandidate
from vrt_auto.candidates import GTIVanillaProtectedTheaterFileCandidate
from vrt_auto.candidates import VTVanillaDNSCandidate
from vrt_auto.candidates import VTVanillaEmailPhishingAttachmentCandidate
from vrt_auto.candidates import VTVanillaEmailPhishingLinkCandidate
from vrt_auto.candidates import VTVanillaFileCandidate
from vrt_auto.candidates import VTVanillaMFTCandidate
from vrt_auto.candidates import VTVanillaProtectedTheaterFileCandidate
from vrt_auto.create import auto_dns
from vrt_auto.create import auto_email_attachment
from vrt_auto.create import auto_email_link
from vrt_auto.create import auto_file
from vrt_auto.create import auto_mft
from vrt_auto.create import auto_protected_theater_from_file
from vrt_auto.utils import VRTAutoClientManager
from vrt_sdk import PartialAction


class TestVRTAutoClientManager:
  def test_manager(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    assert client


class TestCandidates:
  """Test instantiation of Candidates."""

  def test_vtvanillafilecandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaFileCandidate(
        "5efa6973aaab67eadfc9e1a718973925aedad4a0fc7683d6118426422e9f294f",
        client
    )
    assert candidate.file_bytes

  def test_vtvanillamftcandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaMFTCandidate(
        "abfc6267d9437fd06a7dc56e0cb16f3980faca0c4cb74f09aabe978c44037ca8",
        client
    )
    assert candidate.file_target
    assert candidate.file_target.file_bytes

  def test_vtvanilladnscandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaDNSCandidate(
        base64.b64decode(b"c3VpYXRjYXJld1suXWJpeg==").decode(), client
    )
    assert "suiat" in candidate.domain

  def test_vtvanillaemailphishinglinkcandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaEmailPhishingLinkCandidate(
        base64.b64decode(
            b"aHh4cHM6Ly9naXRjb2Rlc1suXXRvZGF5L2g1eWM4MHliLw==").decode(),
        client
    )
    assert "gitcodes" in candidate.url

  def test_vtvanillaemailphishingattachmentcandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaEmailPhishingAttachmentCandidate(
        "b359c62e6121c0b84ff5b3a754ed8b75ee41d7c84626f6515d34e0c8c81697a2",
        client
    )
    assert candidate.file_target
    assert candidate.file_target.file_bytes

  def test_vtvanillaprotectedtheaterfilecandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaProtectedTheaterFileCandidate(
        "0ccb97a3f92d7624c27f0ef188180c528481ba00102e4cadf942fd703fff689c",
        client
    )
    assert candidate.file_target
    assert candidate.file_target.file_bytes
    assert len(candidate.factory.commands) > 0

  def test_gtivanillafilecandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaFileCandidate(
        "0500fad5db9bf8ffc3724f58b977eb9ed4aea466311ab7d3a0c8601f3b7f35e2",
        client
    )
    assert candidate.file_bytes

  def test_gtivanillamftcandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaMFTCandidate(
        "de1ebf04ec979c143b68a22f509b2aad5119e80399143fb055023df7832acba7",
        client
    )
    assert candidate.file_target
    assert candidate.file_target.file_bytes

  def test_gtivanilladnscandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaDNSCandidate(
        base64.b64decode(b"Y3ViYXdlYmNhcnNbLl1jb20=").decode(), client)
    assert "cubawebcars" in candidate.domain

  def test_gtivanillaemailphishinglinkcandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaPhishingLinkCandidate(
        base64.b64decode(
            b"aHh4cHM6Ly9hbmRyaXhkZXNpZ25bLl1jb20va3p6L2MzdWJbLl16aXA=").decode(),
        client
    )
    assert "andrixdesign" in candidate.url

  def test_gtivanillaemailphishingattachmentcandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaPhishingAttachmentCandidate(
        "a575b1c6a1a01ac9b2f65e3143152abbd7ade4acf8c2df7a5a9cb00ffb3d051d",
        client
    )
    assert candidate.file_target
    assert candidate.file_target.file_bytes

  def test_gtivanillaprotectedtheaterfilecandidate(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaProtectedTheaterFileCandidate(
        "839c7a14022e594dd935dcaf51e3a326758b0d92207585ec139e56eb6d2f3171",
        client
    )
    assert candidate.file_target
    assert candidate.file_target.file_bytes
    assert len(candidate.factory.commands) > 0


class TestVT:
  """Test creation of Actions using VirusTotal as a source."""

  def test_vt_file(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaFileCandidate(
        "5efa6973aaab67eadfc9e1a718973925aedad4a0fc7683d6118426422e9f294f",
        client
    )
    response = auto_file(client, candidate)
    assert isinstance(response, int)

  def test_vt_mft(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaMFTCandidate(
        "abfc6267d9437fd06a7dc56e0cb16f3980faca0c4cb74f09aabe978c44037ca8",
        client
    )
    response = auto_mft(client, candidate)
    assert isinstance(response, PartialAction)

  def test_vt_dns(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaDNSCandidate(
        base64.b64decode(b"c3VpYXRjYXJldy5iaXo=").decode(), client)
    response = auto_dns(client, candidate)
    assert isinstance(response, PartialAction)

  def test_vt_phish_link(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaEmailPhishingLinkCandidate(
        base64.b64decode(
            b"aHR0cHM6Ly9naXRjb2Rlcy50b2RheS9oNXljODB5Yi8=").decode(),
        client
    )
    response = auto_email_link(client, candidate)
    assert isinstance(response, PartialAction)

  def test_vt_phish_attach(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaEmailPhishingAttachmentCandidate(
        "b359c62e6121c0b84ff5b3a754ed8b75ee41d7c84626f6515d34e0c8c81697a2",
        client
    )
    response = auto_email_attachment(client, candidate)
    assert isinstance(response, PartialAction)

  def test_vt_protected_theater_from_file(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = VTVanillaProtectedTheaterFileCandidate(
        "0ccb97a3f92d7624c27f0ef188180c528481ba00102e4cadf942fd703fff689c",
        client
    )
    response = auto_protected_theater_from_file(client, candidate)
    assert isinstance(response, PartialAction)


class TestGTI:
  """Test creation of Actions using Google Threat Intelligence as a source."""

  def test_gti_file(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaFileCandidate(
        "0500fad5db9bf8ffc3724f58b977eb9ed4aea466311ab7d3a0c8601f3b7f35e2",
        client
    )
    response = auto_file(client, candidate)
    assert isinstance(response, int)

  def test_gti_mft(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaMFTCandidate(
        "de1ebf04ec979c143b68a22f509b2aad5119e80399143fb055023df7832acba7",
        client
    )
    response = auto_mft(client, candidate)
    assert isinstance(response, PartialAction)

  def test_gti_dns(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaDNSCandidate(
        base64.b64decode(b"Y3ViYXdlYmNhcnMuY29t").decode(), client)
    response = auto_dns(client, candidate)
    assert isinstance(response, PartialAction)

  def test_gti_phish_link(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaPhishingLinkCandidate(
        base64.b64decode(
            b"aHR0cHM6Ly9hbmRyaXhkZXNpZ24uY29tL2t6ei9jM3ViLnppcA==").decode(),
        client
    )
    response = auto_email_link(client, candidate)
    assert isinstance(response, PartialAction)

  def test_gti_phish_attach(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    candidate = GTIVanillaPhishingAttachmentCandidate(
        "a575b1c6a1a01ac9b2f65e3143152abbd7ade4acf8c2df7a5a9cb00ffb3d051d",
        client
    )
    response = auto_email_attachment(client, candidate)
    assert isinstance(response, PartialAction)

  def test_gti_protected_theater_from_file(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)
    # Also tests creation from existing file
    candidate = GTIVanillaProtectedTheaterFileCandidate(
        "a575b1c6a1a01ac9b2f65e3143152abbd7ade4acf8c2df7a5a9cb00ffb3d051d",
        client
    )
    response = auto_protected_theater_from_file(client, candidate)
    assert isinstance(response, PartialAction)


class TestOther:
  """Test other code paths not covered above."""

  def test_malware_assoc(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)

    candidate = VTVanillaMFTCandidate(
        "cdd0fdf91cc680158996b4ea1a4697d9d95d29244fbb4cd9a74ed95423941543",
        client
    )
    response = auto_mft(client, candidate)
    assert isinstance(response, PartialAction)

    candidate = GTIVanillaProtectedTheaterFileCandidate(
        "cdd0fdf91cc680158996b4ea1a4697d9d95d29244fbb4cd9a74ed95423941543",
        client
    )
    response = auto_protected_theater_from_file(client, candidate)
    assert isinstance(response, PartialAction)

  def test_vuln_assoc(self, test_dir):
    client = VRTAutoClientManager(target_director=test_dir)

    candidate = VTVanillaMFTCandidate(
        "c372c6d85fa2f0178b7a6b06df12d6b03221e52e0e1df05bd34dabdf98a65c3c",
        client
    )
    response = auto_mft(client, candidate)
    assert isinstance(response, PartialAction)

    candidate = GTIVanillaProtectedTheaterFileCandidate(
        "c372c6d85fa2f0178b7a6b06df12d6b03221e52e0e1df05bd34dabdf98a65c3c",
        client
    )
    response = auto_protected_theater_from_file(client, candidate)
    assert isinstance(response, PartialAction)
