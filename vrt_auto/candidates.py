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

import uuid
from vrt_auto.utils import calculate_vt_gti_url_id
from vrt_auto.utils import sha256_hash
from vrt_auto.utils import VRTAutoClientManager
from vrt_sdk import AttackerLocationDimensionEnum
from vrt_sdk import AttackVectorDimensionEnum
from vrt_sdk import BehaviorTypeDimensionEnum
from vrt_sdk import ControlTagEnum
from vrt_sdk import CovertDimensionEnum
from vrt_sdk import HostActionFactory
from vrt_sdk import OSPlatformDimensionEnum
from vrt_sdk import OSTagEnum
from vrt_sdk import SrcDstTagEnum
from vrt_sdk import StageOfAttackDimensionEnum


class Candidate:
  """Base class defining some type of artifact to make MSV content from."""
  pass


class AbstractActionCandidate(Candidate):
  """Defines a type of Candidate used to create an Action."""

  def __init__(self):
    """Defines a type of Candidate used to create an Action.

    Attributes for an AbstractActionCandidate include:

    - action_title (str) - Prepopulated with "(VRT Auto) - {UUID4}"
    - action_description (str) - Prepopulated with "This is an Action created
      using VRT Auto."
    - user_tags (list[str]) - Prepopulated with "VRT_AUTO"
    - user_run_as_tags (list[str])
    - user_src_dst_tags (list[str])
    - user_os_tags (list[str])
    - user_control_tags (list[str])
    - user_mitre_mitigation_tags (list[str])
    - user_nist_control_tags (list[str])
    """

    super().__init__()
    self.action_title: str = "(VRT Auto) - " + str(uuid.uuid4())
    self.action_description: str = "This is an Action created using VRT Auto."
    self.user_tags: list[str] = ["VRT_AUTO"]
    self.user_run_as_tags: list[str] = []
    self.user_src_dst_tags: list[str] = []
    self.user_os_tags: list[str] = []
    self.user_control_tags: list[str] = []
    self.user_mitre_mitigation_tags: list[str] = []
    self.user_nist_control_tags: list[str] = []


class AbstractFileCandidate(Candidate):
  """Defines a type of Candidate used to create a file."""

  def __init__(self):
    """Init method for AbstractFileCandidate.

    Attributes for an AbstractFileCandidate include:

    - file_hash (str)
    - file_bytes (bytes)
    - file_name (str) - Prepopulated with "AbstractFileCandidate_{UUID4}"
    - file_description (str) - Prepopulated with "AbstractFileCandidate
      Description Placeholder"
    - operating_system (OSPlatformDimensionEnum) - Prepopulated with
      GENERAL_OS_PLATFORM
    - user_tags (list[str]) - Prepopulated with "VRT_AUTO"
    """

    super().__init__()
    self.file_hash: str = ""
    self.file_bytes: bytes = b""
    self.file_name: str = "AbstractFileCandidate_" + str(uuid.uuid4())
    self.file_description: str = "AbstractFileCandidate Description Placeholder"
    self.operating_system: OSPlatformDimensionEnum = OSPlatformDimensionEnum.GENERAL_OS_PLATFORM
    self.user_tags: list[str] = ["VRT_AUTO"]


class AbstractMFTActionCandidate(AbstractActionCandidate):
  """Defines a type of Candidate used to create an MFT Action."""

  def __init__(self):
    """Init method for AbstractMFTActionCandidate.

    Attributes for an AbstractMFTActionCandidate include:

    - action_title (str) - Prepopulated with "File Transfer (VRT Auto) -
      {UUID4}"
    - action_description (str) - Prepopulated with "This is an Action created
      using VRT Auto."
    - user_tags (list[str]) - Prepopulated with "VRT_AUTO"
    - user_run_as_tags (list[str])
    - user_src_dst_tags (list[str])
    - user_os_tags (list[str]) - Prepopulated with "ANY"
    - user_control_tags (list[str])
    - user_mitre_mitigation_tags (list[str])
    - user_nist_control_tags (list[str])
    - file_target (AbstractFileCandidate)
    """
    super().__init__()
    self.action_title = f"File Transfer (VRT Auto) - {str(uuid.uuid4())}"
    self.user_os_tags.append(OSTagEnum.ANY.value)
    self.file_target: AbstractFileCandidate | None = None


class AbstractDNSActionCandidate(AbstractActionCandidate):
  """Defines a type of Candidate used to create a DNS Action."""

  def __init__(self):
    """Init method for AbstractDNSActionCandidate.

    Attributes for an AbstractDNSActionCandidate include:

    - action_title (str) - Prepopulated with "DNS Query (VRT Auto) - {UUID4}"
    - action_description (str) - Prepopulated with "This is an Action created
      using VRT Auto."
    - user_tags (list[str]) - Prepopulated with "ATT&CK:T1071.004"
    - user_run_as_tags (list[str])
    - user_src_dst_tags (list[str])
    - user_os_tags (list[str]) - Prepopulated with "ANY"
    - user_control_tags (list[str])
    - user_mitre_mitigation_tags (list[str])
    - user_nist_control_tags (list[str])
    - domain (str)
    """
    super().__init__()
    self.action_title = f"DNS Query (VRT Auto) - {str(uuid.uuid4())}"
    self.user_tags.append("ATT&CK:T1071.004")
    self.user_os_tags.append(OSTagEnum.ANY.value)
    self.domain: str = ""


class AbstractEmailNoAttachmentActionCandidate(AbstractActionCandidate):
  """Defines a type of Candidate used to create an Email Action w/o an attachment."""

  def __init__(self):
    """Init method for AbstractPhishingLinkActionCandidate.

    Attributes for an AbstractPhishingLinkActionCandidate include:

    - action_title (str) - Prepopulated with "Email (No Attachment) (VRT Auto) -
       {UUID4}"
    - action_description (str) - Prepopulated with "This is an Action created
      using VRT Auto."
    - user_tags (list[str]) - Prepopulated with "VRT_AUTO"
    - user_run_as_tags (list[str])
    - user_src_dst_tags (list[str])
    - user_os_tags (list[str]) - Prepopulated with "ANY"
    - user_control_tags (list[str]) - Prepopulated with "Email"
    - user_mitre_mitigation_tags (list[str])
    - user_nist_control_tags (list[str])
    - body (str)
    """
    super().__init__()
    self.action_title = f"Email (No Attachment) (VRT Auto) - {str(uuid.uuid4())}"
    self.user_os_tags.append(OSTagEnum.ANY.value)
    self.user_control_tags.append(ControlTagEnum.EMAIL.value)

    self.body: str = ""


class AbstractEmailAttachmentActionCandidate(AbstractActionCandidate):
  """Defines a type of Candidate used to create an Email Action with an attachment."""

  def __init__(self):
    """Init method for AbstractPhishingAttachmentActionCandidate.

    Attributes for an AbstractPhishingAttachmentActionCandidate include:

    - action_title (str) - Prepopulated with "Email (Attachment) (VRT Auto) -
      {UUID4}"
    - action_description (str) - Prepopulated with "This is an Action created
      using VRT Auto."
    - user_tags (list[str]) - Prepopulated with "VRT_AUTO"
    - user_run_as_tags (list[str])
    - user_src_dst_tags (list[str])
    - user_os_tags (list[str]) - Prepopulated with "ANY"
    - user_control_tags (list[str]) - Prepopulated with "Email"
    - user_mitre_mitigation_tags (list[str])
    - user_nist_control_tags (list[str])
    - file_target (AbstractFileCandidate)
    - body (str) - Prepopulated with "Placeholder"
    """
    super().__init__()
    self.action_title = f"Email (Attachment) (VRT Auto) - {str(uuid.uuid4())}"
    self.user_os_tags.append(OSTagEnum.ANY.value)
    self.user_control_tags.append(ControlTagEnum.EMAIL.value)
    self.file_target: AbstractFileCandidate | None = None
    self.body: str = "Placeholder"


class AbstractProtectedTheaterFileActionCandidate(AbstractActionCandidate):
  """Defines a type of Candidate used to create a Protected Theater Action from a file."""

  def __init__(self):
    r"""Init method for AbstractProtectedTheaterActionCandidate.

    Attributes for an AbstractProtectedTheaterActionCandidate include:

    - action_title (str) - "Prepopulated with Protected Theater (VRT Auto) -
      {UUID4}"
    - action_description (str) - Prepopulated with "This is an Action created
      using VRT Auto."
    - user_tags (list[str]) - Prepopulated with "VRT_AUTO"
    - user_run_as_tags (list[str])
    - user_src_dst_tags (list[str])
    - user_os_tags (list[str])
    - user_control_tags (list[str]) - Prepopulated with "Endpoint"
    - user_mitre_mitigation_tags (list[str])
    - user_nist_control_tags (list[str])
    - file_target (AbstractFileCandidate)
    - action_file_path (str) - Prepopulated with "C:\Users\Public\Documents\"
    - action_file_name (str)
    """
    super().__init__()
    self.action_title = f"Protected Theater (VRT Auto) - {str(uuid.uuid4())}"
    self.user_control_tags.append(ControlTagEnum.ENDPOINT.value)
    self.file_target: AbstractFileCandidate | None = None
    self.action_file_path = "C:\\Users\\Public\\Documents\\"
    self.action_file_name = ""
    self.factory: HostActionFactory | None = None


class VTVanillaFileCandidate(AbstractFileCandidate):
  """Candidate used to create a file from VirusTotal."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()
    self.file_hash = file_hash
    self.file_bytes = cm.download_file_from_vt(self.file_hash)
    self.file_name = sha256_hash(self.file_bytes) + ".mal_"
    self.file_description = "A file obtained from VirusTotal created using VRT Auto."


class VTVanillaMFTCandidate(AbstractMFTActionCandidate):
  """Candidate used to create an MFT Action from VirusTotal."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()

    file_report = cm.get_file_report_from_vt(file_hash)

    self.file_target = VTVanillaFileCandidate(file_hash, cm)

    self.action_title = f"Malicious File Transfer (VRT Auto - VT) - {self.file_target.file_hash}"
    self.action_description = f"""This is a Malicious File Transfer Action created using VRT Auto.

---

**VirusTotal IOC Page**: {f"[{file_hash}](https://www.virustotal.com/gui/file/{file_hash})"}

**Last analysis date (as of Action creation)**: {file_report.last_analysis_date}

**Malicious verdicts**: _{file_report.last_analysis_stats["malicious"]}_

**Suspicious verdicts**: _{file_report.last_analysis_stats["suspicious"]}_
"""

    self.user_tags.append("ATT&CK:T1105")
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_INTERNAL_TRUSTED_DST_EXTERNAL_UNTRUSTED.value)
    self.user_control_tags.append(ControlTagEnum.IDS_IPS.value)
    self.user_control_tags.append(ControlTagEnum.NGFW.value)
    self.user_control_tags.append(ControlTagEnum.PROXY.value)


class VTVanillaDNSCandidate(AbstractDNSActionCandidate):
  """Candidate used to create a DNS Action from VirusTotal."""

  def __init__(self, domain: str, cm: VRTAutoClientManager):
    super().__init__()

    self.domain = domain

    domain_report = cm.get_domain_report_from_vt(domain)

    self.action_title = f"Malicious DNS Query (VRT Auto - VT) - {self.domain.replace('http', 'hxxp').replace('.', '[.]')}"
    self.action_description = f"""This is a Malicious DNS Query Action created using VRT Auto.
    
---

**VirusTotal IOC Page**: {f"[{domain.replace('.', '[.]').replace('http', 'hxxp')}](https://www.virustotal.com/gui/domain/{domain})"}

**Last analysis date (as of Action creation)**: {domain_report.last_analysis_date}

**Malicious verdicts**: _{domain_report.last_analysis_stats["malicious"]}_

**Suspicious verdicts**: _{domain_report.last_analysis_stats["suspicious"]}_
"""

    self.user_src_dst_tags.append(SrcDstTagEnum.SRC_INTERNAL_TRUSTED.value)
    self.user_control_tags.append(ControlTagEnum.IDS_IPS.value)
    self.user_control_tags.append(ControlTagEnum.NGFW.value)
    self.user_control_tags.append(ControlTagEnum.PROXY.value)


class VTVanillaEmailPhishingLinkCandidate(
    AbstractEmailNoAttachmentActionCandidate):
  """Candidate used to create a Phishing Email (Link) Action from VirusTotal."""

  def __init__(self, url: str, cm: VRTAutoClientManager):
    super().__init__()
    self.url = url

    url_report = cm.get_url_report_from_vt(url)

    self.action_title = f"Phishing Email, Malicious Link (VRT Auto - VT) - {self.url.replace('http', 'hxxp').replace('.', '[.]')}"
    self.action_description = f"""This is a Phishing Email (Link) Action created using VRT Auto.

---

**VirusTotal IOC Page**: {f"[{url.replace('.', '[.]').replace('http', 'hxxp')}](https://www.virustotal.com/gui/url/{calculate_vt_gti_url_id(url)})"}

**Last analysis date (as of Action creation)**: {url_report.last_analysis_date}

**Malicious verdicts**: _{url_report.last_analysis_stats["malicious"]}_

**Suspicious verdicts**: _{url_report.last_analysis_stats["suspicious"]}_
"""

    self.user_tags.append("ATT&CK:T1204.001")
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED.value)
    self.body = url


class VTVanillaEmailPhishingAttachmentCandidate(
    AbstractEmailAttachmentActionCandidate):
  """Candidate used to create a Phishing Email (Attachment) Action from VirusTotal."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()

    self.file_target = VTVanillaFileCandidate(file_hash, cm)
    file_report = cm.get_file_report_from_vt(file_hash)

    self.action_title = f"Phishing Email, Malicious Attachment (VRT Auto - VT) - {self.file_target.file_hash}"
    self.action_description = f"""This is a Phishing Email (Attachment) Action created using VRT Auto.

---

**VirusTotal IOC Page**: {f"[{file_hash}](https://www.virustotal.com/gui/file/{file_hash})"}

**Last analysis date (as of Action creation)**: {file_report.last_analysis_date}

**Malicious verdicts**: _{file_report.last_analysis_stats["malicious"]}_

**Suspicious verdicts**: _{file_report.last_analysis_stats["suspicious"]}_
"""

    self.user_tags.append("ATT&CK:T1566.001")
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED.value)


class VTVanillaProtectedTheaterFileCandidate(
    AbstractProtectedTheaterFileActionCandidate):
  """Candidate used to create a Protected Theater Action from VirusTotal."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()

    self.file_target = GTIVanillaFileCandidate(file_hash, cm)

    self.action_file_name = file_hash + ".exe"  # Hardcoded assumption of PE exe

    file_report = cm.get_file_report_from_gti(file_hash)

    self.action_title = f"Protected Theater (VRT Auto - VT) - {self.file_target.file_hash}"
    self.action_description = f"""This is a Protected Theater Action created using VRT Auto.

**Be aware that this Action is not guaranteed to execute as is, and may require modification to run properly. By default, it will assume (with NO justification) that all files provided are PE files and attempt to execute them directly.**

---

**VirusTotal IOC Page**: {f"[{file_hash}](https://www.virustotal.com/gui/file/{file_hash})"}

**Last analysis date (as of Action creation)**: {file_report.last_analysis_date}

**Malicious verdicts**: _{file_report.last_analysis_stats["malicious"]}_

**Suspicious verdicts**: _{file_report.last_analysis_stats["suspicious"]}_
"""

    self.factory = HostActionFactory(self.action_title, self.action_description,
                                     "cmd.exe")

    cm.director_client.set_host_factory_dimensions(self.factory,
                                                   AttackVectorDimensionEnum.GENERAL_VECTOR,
                                                   AttackerLocationDimensionEnum.INTERNAL,
                                                   BehaviorTypeDimensionEnum.MALWARE_EXECUTION,
                                                   CovertDimensionEnum.NO,
                                                   OSPlatformDimensionEnum.WINDOWS,
                                                   StageOfAttackDimensionEnum.EXECUTION)

    self.factory.add_step(self.action_file_path + self.action_file_name)

    self.user_src_dst_tags.append(SrcDstTagEnum.SRC_INTERNAL_TRUSTED.value)


class GTIVanillaFileCandidate(AbstractFileCandidate):
  """Candidate used to create a file from Google Threat Intelligence."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()
    self.file_hash = file_hash
    self.file_bytes = cm.download_file_from_gti(self.file_hash)
    self.file_name = sha256_hash(self.file_bytes) + ".mal_"
    self.file_description = "A file obtained from Google Threat Intelligence using VRT Auto."


class GTIVanillaMFTCandidate(AbstractMFTActionCandidate):
  """Candidate used to create an MFT Action from Google Threat Intelligence."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()

    self.file_target = GTIVanillaFileCandidate(file_hash, cm)
    file_report = cm.get_file_report_from_gti(file_hash)

    for tag in cm.get_tags_from_report_relationships(file_report):
      self.user_tags.append(tag)

    self.action_title = f"Malicious File Transfer (VRT Auto - GTI) - {self.file_target.file_hash}"
    self.action_description = f"""This is a Malicious File Transfer Action created using VRT Auto.

---

**Google Threat Intelligence IOC Page**: {f"[{file_hash}](https://www.virustotal.com/gui/file/{file_hash})"}

**Last analysis date (as of Action creation)**: {file_report.last_analysis_date}

**GTI Threat Score:** _{file_report.gti_assessment.data["threat_score"].data["value"]}_

**GTI Verdict:** _{file_report.gti_assessment.data["verdict"].data["value"].replace("VERDICT_", "")}_
"""

    self.user_tags.append("ATT&CK:T1105")
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_INTERNAL_TRUSTED_DST_EXTERNAL_UNTRUSTED.value)
    self.user_control_tags.append(ControlTagEnum.IDS_IPS.value)
    self.user_control_tags.append(ControlTagEnum.NGFW.value)
    self.user_control_tags.append(ControlTagEnum.PROXY.value)


class GTIVanillaDNSCandidate(AbstractDNSActionCandidate):
  """Candidate used to create a DNS Action from Google Threat Intelligence."""

  def __init__(self, domain: str, cm: VRTAutoClientManager):
    super().__init__()

    self.domain = domain

    domain_report = cm.get_domain_report_from_gti(domain)

    for tag in cm.get_tags_from_report_relationships(domain_report):
      self.user_tags.append(tag)

    self.action_title = f"Malicious DNS Query (VRT Auto - GTI) - {self.domain.replace('http', 'hxxp').replace('.', '[.]')}"
    self.action_description = f"""This is a Malicious DNS Query Action created using VRT Auto.
    
---

**Google Threat Intelligence IOC Page**: {f"[{domain.replace('.', '[.]').replace('http', 'hxxp')}](https://www.virustotal.com/gui/domain/{domain})"}

**Last analysis date (as of Action creation)**: {domain_report.last_analysis_date}

**GTI Threat Score:** _{domain_report.gti_assessment.data["threat_score"].data["value"]}_

**GTI Verdict:** _{domain_report.gti_assessment.data["verdict"].data["value"].replace("VERDICT_", "")}_
"""

    self.user_src_dst_tags.append(SrcDstTagEnum.SRC_INTERNAL_TRUSTED.value)
    self.user_control_tags.append(ControlTagEnum.IDS_IPS.value)
    self.user_control_tags.append(ControlTagEnum.NGFW.value)
    self.user_control_tags.append(ControlTagEnum.PROXY.value)


class GTIVanillaPhishingLinkCandidate(
    AbstractEmailNoAttachmentActionCandidate):
  """Candidate used to create a Phishing Email (Link) Action from Google Threat Intelligence."""

  def __init__(self, url: str, cm: VRTAutoClientManager):
    super().__init__()
    self.url = url

    url_report = cm.get_url_report_from_gti(url)

    for tag in cm.get_tags_from_report_relationships(url_report):
      self.user_tags.append(tag)

    self.action_title = f"Phishing Email, Malicious Link (VRT Auto - GTI) - {self.url.replace('http', 'hxxp').replace('.', '[.]')}"
    self.action_description = f"""This is a Phishing Email (Link) Action created using VRT Auto.

---

**Google Threat Intelligence IOC Page**: {f"[{url.replace('.', '[.]').replace('http', 'hxxp')}](https://www.virustotal.com/gui/url/{calculate_vt_gti_url_id(url)})"}

**Last analysis date (as of Action creation)**: {url_report.last_analysis_date}

**GTI Threat Score:** _{url_report.gti_assessment.data["threat_score"].data["value"]}_

**GTI Verdict:** _{url_report.gti_assessment.data["verdict"].data["value"].replace("VERDICT_", "")}_
"""

    self.user_tags.append("ATT&CK:T1204.001")
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED.value)
    self.body = url


class GTIVanillaPhishingAttachmentCandidate(
    AbstractEmailAttachmentActionCandidate):
  """Candidate used to create a Phishing Email (Attachment) Action from Google Threat Intelligence."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()

    self.file_target = GTIVanillaFileCandidate(file_hash, cm)
    file_report = cm.get_file_report_from_gti(file_hash)

    for tag in cm.get_tags_from_report_relationships(file_report):
      self.user_tags.append(tag)

    self.action_title = f"Phishing Email, Malicious Attachment (VRT Auto - GTI) - {self.file_target.file_hash}"
    self.action_description = f"""This is a Phishing Email (Attachment) Action created using VRT Auto.

---

**Google Threat Intelligence IOC Page**: {f"[{file_hash}](https://www.virustotal.com/gui/file/{file_hash})"}

**Last analysis date (as of Action creation)**: {file_report.last_analysis_date}

**GTI Threat Score:** _{file_report.gti_assessment.data["threat_score"].data["value"]}_

**GTI Verdict:** _{file_report.gti_assessment.data["verdict"].data["value"].replace("VERDICT_", "")}_
"""

    self.user_tags.append("ATT&CK:T1566.001")
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED.value)


class GTIVanillaProtectedTheaterFileCandidate(
    AbstractProtectedTheaterFileActionCandidate):
  """Candidate used to create a Protected Theater Action from Google Threat Intelligence."""

  def __init__(self, file_hash: str, cm: VRTAutoClientManager):
    super().__init__()

    self.file_target = GTIVanillaFileCandidate(file_hash, cm)

    self.action_file_name = file_hash + ".exe"  # Hardcoded assumption of PE exe

    file_report = cm.get_file_report_from_gti(file_hash)

    for tag in cm.get_tags_from_report_relationships(file_report):
      self.user_tags.append(tag)

    self.action_title = f"Protected Theater (VRT Auto - GTI) - {self.file_target.file_hash}"
    self.action_description = f"""This is a Protected Theater Action created using VRT Auto.

**Be aware that this Action is not guaranteed to execute as is, and may require modification to run properly. By default, it will assume (with NO justification) that all files provided are PE files and attempt to execute them directly.** 

---

**Google Threat Intelligence IOC Page**: {f"[{file_hash}](https://www.virustotal.com/gui/file/{file_hash})"}

**Last analysis date (as of Action creation)**: {file_report.last_analysis_date}

**GTI Threat Score:** _{file_report.gti_assessment.data["threat_score"].data["value"]}_

**GTI Verdict:** _{file_report.gti_assessment.data["verdict"].data["value"].replace("VERDICT_", "")}_
"""

    self.factory = HostActionFactory(self.action_title, self.action_description,
                                     "cmd.exe")

    cm.director_client.set_host_factory_dimensions(self.factory,
                                                   AttackVectorDimensionEnum.GENERAL_VECTOR,
                                                   AttackerLocationDimensionEnum.INTERNAL,
                                                   BehaviorTypeDimensionEnum.MALWARE_EXECUTION,
                                                   CovertDimensionEnum.NO,
                                                   OSPlatformDimensionEnum.WINDOWS,
                                                   StageOfAttackDimensionEnum.EXECUTION)

    self.factory.add_step(self.action_file_path + self.action_file_name)

    self.user_src_dst_tags.append(SrcDstTagEnum.SRC_INTERNAL_TRUSTED.value)
