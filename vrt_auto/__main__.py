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

import argparse
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

if __name__ == "__main__":
  PARSER = argparse.ArgumentParser()
  PARSER.formatter_class = argparse.RawDescriptionHelpFormatter
  PARSER.description = r"""
VRT Auto - Create Mandiant Security Validation Content automatically.

Provided by Google Threat Intelligence Group Validation Research Team.

No guarantees are provided regarding the performance of this tool.

Example usage:
 - python -m vrt_auto local vt_file a1b2....c3d4
 - python -m vrt_auto rnd1 vt_mft a1b2....c3d4
 - python -m vrt_auto rnd1 gti_dns www.mandiant.com
 - python -m vrt_auto rnd2 vt_phish_link https://cloud.google.com/security/products/threat-intelligence
 - python -m vrt_auto rnd1 gti_phish_link hxxps://cloud[.]google[.]com/security/products/threat-intelligence
 - python -m vrt_auto rnd2 vt_pt a1b2....c3d4
 - python -m vrt_auto rnd2 gti_pt a1b2....c3d4
"""
  PARSER.add_argument("director")

  subparsers = PARSER.add_subparsers(title="Operation types")

  file_parser = subparsers.add_parser(
      "vt_file",
      help="Create a file in the file library from a file on VirusTotal."
           " Limited metadata provided.")

  mft_parser = subparsers.add_parser(
      "vt_mft",
      help="Create a Malicious File Transfer Action from a file on VirusTotal."
           " Will perform an HTTP GET request over port 80."
           " Will place the target file in the file library if it does not"
           " already exist. Limited metadata provided.")
  mft_parser.set_defaults(operation="vt_mft")

  dns_parser = subparsers.add_parser(
      "vt_dns",
      help="Create a Malicious DNS Query Action from a domain on VirusTotal."
           " Will perform an A record lookup. Limited metadata provided.")
  dns_parser.set_defaults(operation="vt_dns")

  phish_link_parser = subparsers.add_parser(
      "vt_phish_link",
      help="Create a Phishing Email Action from a URL on VirusTotal."
           " Limited metadata provided.")
  phish_link_parser.set_defaults(operation="vt_phish_link")

  phish_attach_parser = subparsers.add_parser(
      "vt_phish_attach",
      help="Create a Phishing Email Action from a file on VirusTotal."
           " Will place the target file in the file library if it does not"
           " already exist. Limited metadata provided.")
  phish_attach_parser.set_defaults(operation="vt_phish_attach")

  pt_parser = subparsers.add_parser(
      "vt_pt",
      help="Create a Protected Theater Action from a file on VirusTotal."
           " THIS ACTION IS NOT GUARANTEED TO EXECUTE SUCCESSFULLY AS IS."
           " The Action will use the \"cmd.exe\" command prompt and will assume"
           " the file is an executable binary. Will place the target file in"
           " the file library if it does not already exist."
           " Limited metadata provided.")
  pt_parser.set_defaults(operation="vt_pt")

  gti_file_parser = subparsers.add_parser(
      "gti_file",
      help="Create a file in the file library from a file on Google Threat"
           " Intelligence.")

  gti_mft_parser = subparsers.add_parser(
      "gti_mft",
      help="Create a Malicious File Transfer Action from a file on Google"
           " Threat Intelligence. Will perform an HTTP GET request over port"
           " 80. Will place the target file in the file library if it does"
           " not already exist.")
  gti_mft_parser.set_defaults(operation="gti_mft")

  gti_dns_parser = subparsers.add_parser(
      "gti_dns",
      help="Create a Malicious DNS Query Action from a domain on Google"
           " Threat Intelligence. Will perform an A record lookup.")
  gti_dns_parser.set_defaults(operation="gti_dns")

  gti_phish_link_parser = subparsers.add_parser(
      "gti_phish_link",
      help="Create a Phishing Email Action from a URL on Google Threat"
           " Intelligence.")
  gti_phish_link_parser.set_defaults(operation="gti_phish_link")

  gti_phish_attach_parser = subparsers.add_parser(
      "gti_phish_attach",
      help="Create a Phishing Email Action from a file on Google Threat"
           " Intelligence. Will place the target file in the file library if "
           "it does not already exist.")
  gti_phish_attach_parser.set_defaults(operation="gti_phish_attach")

  gti_pt_parser = subparsers.add_parser(
      "gti_pt",
      help="Create a Protected Theater Action from a file on Google Threat "
           "Intelligence. THIS ACTION IS NOT GUARANTEED TO EXECUTE SUCCESSFULLY"
           " AS IS. The Action will use the \"cmd.exe\" command prompt and will"
           " assume the file is an executable binary. Will place the target"
           " file in the file library if it does not already exist.")
  gti_pt_parser.set_defaults(operation="gti_pt")

  PARSER.add_argument("value")

  args = PARSER.parse_args()

  client_manager = VRTAutoClientManager(args.director)

  if args.operation == "vt_file":
    auto_file(client_manager,
              VTVanillaFileCandidate(args.value, client_manager))
  elif args.operation == "vt_mft":
    auto_mft(client_manager, VTVanillaMFTCandidate(args.value, client_manager))
  elif args.operation == "vt_dns":
    auto_dns(client_manager,
             VTVanillaDNSCandidate(args.value.replace("[.]", "."),
                                   client_manager))
  elif args.operation == "vt_phish_link":
    auto_email_link(client_manager,
                    VTVanillaEmailPhishingLinkCandidate(
                        args.value.replace("http", "hxxp").replace("[.]", "."),
                        client_manager))
  elif args.operation == "vt_phish_attach":
    auto_email_attachment(client_manager,
                          VTVanillaEmailPhishingAttachmentCandidate(
                              args.value,
                              client_manager))
  elif args.operation == "vt_pt":
    auto_protected_theater_from_file(client_manager,
                                     VTVanillaProtectedTheaterFileCandidate(
                                         args.value,
                                         client_manager))

  elif args.operation == "gti_file":
    auto_file(client_manager,
              GTIVanillaFileCandidate(args.value, client_manager))
  elif args.operation == "gti_mft":
    auto_mft(client_manager, GTIVanillaMFTCandidate(args.value, client_manager))
  elif args.operation == "gti_dns":
    auto_dns(client_manager,
             GTIVanillaDNSCandidate(args.value.replace("[.]", "."),
                                    client_manager))
  elif args.operation == "gti_phish_link":
    auto_email_link(client_manager,
                    GTIVanillaPhishingLinkCandidate(
                        args.value.replace("http", "hxxp").replace("[.]", "."),
                        client_manager))
  elif args.operation == "gti_phish_attach":
    auto_email_attachment(client_manager,
                          GTIVanillaPhishingAttachmentCandidate(args.value,
                                                                client_manager))
  elif args.operation == "gti_pt":
    auto_protected_theater_from_file(client_manager,
                                     GTIVanillaProtectedTheaterFileCandidate(
                                         args.value,
                                         client_manager))

  else:
    raise ValueError("Invalid choice of action")
