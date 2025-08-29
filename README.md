# VRT-Auto

External version of Google Threat Intelligence Group (GTIG) Validation Research
Team's (VRT) Python tool for automating creation of Mandiant Security
Validation (MSV) Content.

# Disclaimers

## Ownership

This is a modified version of an internal tool developed by VRT specifically for
our team's use cases involving the creation of validation content.

## Reliability & Bug Fixes

The tool is provided **as is** so that external parties can benefit. VRT may
update this code at our discretion. VRT makes no representations or
warranties that this code will operate in other environments, that it is
free from defects, or that future updates will be provided.

## Affiliation with Mandiant Security Validation API

VRT is **not** involved in the creation,
development, or maintenance of the MSV API in any way.
Official documentation for the
Mandiant Security Validation API can be
found [here](https://docs.mandiant.com/home/security-validation-api).

VRT assumes **no responsibility** for addressing any defects, updates, or
changes in the MSV API.

## On-Premises vs. SaaS

The Software-as-a-Service (SaaS) version of MSV is being deprecated.
Consequently, no assurances are provided regarding the reliability of this
library for interaction with SaaS instances.

While most, but not all, functionality is available for SaaS as of the
time of writing, **no** efforts will be undertaken to maintain such
compatibility.

# Requirements

This tool assumes the installation of the _vrt_sdk_ Python package.

Direct execution of the module requires the setup of an ini configuration file
described in the repository for VRT SDK.

For Action creation from VirusTotal and Google Threat Intelligence, the
following entries are required in the ini file.

##### VirusTotal

```ini
[vt]
api_key = {VALUE}
```

##### Google Threat Intelligence

```ini
[gti]
api_key = {VALUE}
```

Custom Action creation methods (described below) can be devised without either
of these values, but all built-in methods of action creation requires one of
the two.

# Installation

Install the VRT-SDK package first.

Then clone this repository and run `pip install .`

# Usage

Follows the general format `python -m vrt_auto {director} {operation}`

`director` is the name of a director as specified in the ini file configured for
the VRT SDK.

See `python -m vrt_auto --help` for a list of all operation descriptions

## VirusTotal (VT) Options

```
python -m vrt_auto dir1 vt_file ioc
python -m vrt_auto dir1 vt_mft ioc
python -m vrt_auto dir1 vt_dns ioc
python -m vrt_auto dir1 vt_phish_link ioc
python -m vrt_auto dir1 vt_phish_attach ioc
python -m vrt_auto dir1 vt_pt ioc
```

## Google Threat Intelligence (GTI) Options

```
python -m vrt_auto dir1 gti_file ioc
python -m vrt_auto dir1 gti_mft ioc
python -m vrt_auto dir1 gti_dns ioc
python -m vrt_auto dir1 gti_phish_link ioc
python -m vrt_auto dir1 gti_phish_attach ioc
python -m vrt_auto dir1 gti_pt ioc
```

# Custom Action Creation

VRT Auto defines a series of `Candidate` class to describe ways of creating MSV
content.

For example, the candidate `VTVanillaDNSCandidate` is a subclass
of `AbstractDNSActionCandidate`, which is a subclass
of `AbstractActionCandidate`.

The method `auto_dns` will accept any subclass of `AbstractDNSActionCandidate`,
such as `VTVanillaDNSCandidate` and `GTIVanillaDNSCandidate`. Both of these
`Candidate` types possess the required attributes (many inherited) for creating
a DNS Action. Some, like `domain`, must be explicitly set during `Candidate`
construction. Others, like `action_description`, are already set in the
superclass, but can be modified as needed.

Generally speaking, each `Candidate` superclass has been configured with as much
detail as can be guaranteed to be applicable. All `AbstractDNSActionCandidate`
classes are guaranteed to exhibit the MITRE Technique `DNS`, so this tag is
applied in that superclass. However, not all Malicious File Transfer Actions
are guaranteed to represent `Ingress Tool Transfer`, so this MITRE Technique tag
is added to the subclasses for `AbstractMFTActionCandidate`, rather than in
`AbstractMFTActionCandidate` itself.

See `CANDIDATES.md` for a list of attributes and their values for each
`Candidate` type.

## Defining a New Candidate for Action Creation

If you want to extend VRT Auto to define a new source of data or metadata scheme
for creating MSV content, you can do this by subclassing.

For example, let's assume you collect malware samples sent to your organization
through phishing emails, and you want to create Phishing Email and Malicious
File Transfer Actions to test against these samples.

Looking at the entry for `AbstractEmailAttachmentActionCandidate`
in `CANDIDATES.md`, we can see the options available for us to set. Much of this
information is also available via the documentation of the
superclass's `__init__` method.

```python
from vrt_auto.candidates import AbstractEmailAttachmentActionCandidate
from vrt_auto.candidates import AbstractFileCandidate
from vrt_auto.candidates import AbstractDNSActionCandidate
from vrt_sdk import ControlTagEnum
from vrt_sdk import SrcDstTagEnum

from hashlib import sha256
from uuid import uuid4


class MyOrgMaliciousDNSCandidate(AbstractDNSActionCandidate):
  def __init__(self, domain: str):
    super().__init__()

    # Candidates that subclass AbstractDNSActionCandidate must define a domain.
    self.domain = domain

    # We override the action title, although we could leave this to the
    # value inherited from AbstractDNSActionCandidate if we wanted.
    self.action_title = f"Malicious DNS Query (My Org) - {self.domain.replace('http', 'hxxp').replace('.', '[.]')}"

    # Add a user tag, to denote that this was phishing observed against our org. 
    self.user_tags.append("my_org_live_phish")

    # We don't need to add a MITRE Technique for DNS, because it is already
    # set in AbstractDNSActionCandidate

    # Define control and src_dst tags
    self.user_src_dst_tags.append(SrcDstTagEnum.SRC_INTERNAL_TRUSTED.value)
    self.user_control_tags.append(ControlTagEnum.IDS_IPS.value)
    self.user_control_tags.append(ControlTagEnum.NGFW.value)
    self.user_control_tags.append(ControlTagEnum.PROXY.value)


class MyOrgFileCandidate(AbstractFileCandidate):
  def __init__(self, local_file_path: str):
    super().__init__()

    self.file_bytes = open(local_file_path, "rb").read()

    self.file_hash = sha256(self.file_bytes).hexdigest()
    self.file_name = "my_org_" + str(uuid4())  # random name

    # We can set file_description here, but we choose not to do so for now, 
    # as we inherit a placeholder string from the superclass

    # Add a user tag, to denote that this was phishing observed against our org.
    self.user_tags.append("my_org_live_phish")


class MyOrgPhishingEmailCandidate(AbstractEmailAttachmentActionCandidate):
  def __init__(self, file_hash: str):
    super().__init__()

    # Candidates subclassing AbstractEmailAttachmentActionCandidate require
    # a file_target attribute containing a candidate subclassing
    # AbstractFileCandidate.
    self.file_target = MyOrgFileCandidate(file_hash)

    # Override the action title and description
    self.action_title = f"Phishing Email, Malicious Attachment (My Org) - {self.file_target.file_hash}"
    self.action_description = f"Phishing Email with an attachment observed targeting our org."

    # AbstractEmailAttachmentActionCandidate does not possess a MITRE Technique
    # by default, as it is conceivable that someone may wish to create Email
    # Actions with attachments that are _not_ necessarily spearphishing.
    # Therefore, we add the MITRE Technique for spearphishing attachments to
    # VTVanillaEmailPhishingAttachmentCandidate rather than its superclass.
    # As this Candidate represents phishing with attachments, we must add
    # this technique to this Candidate as well.
    self.user_tags.append("ATT&CK:T1566.001")

    # Add a user tag, to denote that this was phishing observed against our org.
    self.user_tags.append("my_org_live_phish")

    # AbstractEmailAttachmentActionCandidate already defines the Control:Email
    # tag, so there is no need to set it. However, we DO need to set a src_dst
    # tag denoting that this email is coming from an external source.
    self.user_src_dst_tags.append(
        SrcDstTagEnum.SRC_EXTERNAL_UNTRUSTED_DST_INTERNAL_TRUSTED.value)
```

Now that we have our `Candidate` classes defined, we can create instances of
them and pass them to the `auto_dns` and `auto_email_attachment` functions
defined in `create.py`.

Note that these functions expect an instance of `VRTAutoClientManager` to be
provided, which is a wrapper class holding a Director client, a VirusTotal
client, and a Google Threat Intelligence client. `vt` and `gti` candidates. In
this case, since we are not pulling any data from either platform, we do not
need the entries in the ini file as described above. However, we _do_ still need
the `VRTAutoClientManager` class.

# Extendability

## Evaluations & Sequences

VRT Auto does not support the creation of Evaluations or Sequences, although it
could conceivably be extended to do so.

However, one of the example scripts under the VRT SDK repo does provide an
example script capable of automatically building evaluations from all Actions
with a specific tag.

## Integration with Other Tools

The functionality in `VRT_Auto` can be imported into other tools instead of
executing `VRT_Auto` directly for further customization. This would be useful
for creating a large volume of Actions at once.

To do this, you would import

- `VRTAutoClientManager` from `utils.py`
- Any desired `Candidate` classes from `candidates.py`
- Any desired Action creation methods (i.e. `auto_mft`) from `create.py`

In your tool, you would then follow this pattern

```Python
# import everything described above

# Create a client
client = VRTAutoClientManager("placeholder")


# Define your Candidate. This would not be necessary if you used an existing
# candidate.
# superclass_name is likely AbstractMFTCandidate
class CustomMFTCandidate(superclass_name):
  def __init__(self, some_input):
    # define candidate requirements
    # maybe tag the actions in a very unique way
    # maybe give them some funny names
    pass


# Create a list of Candidates for Action creation
candidates = []
for entry in ["a", "b", "c", "d", "e"]:
  new_candidate = CustomMFTCandidate(entry)
  candidates.append(new_candidate)

# For each Candidate, create an MFT Action
for candidate in candidates:
  auto_mft(client, candidate)
```

Note: `VRTAutoClientManager` can be created given only a `Director` class.
The `vt` and `gti` sections in the ini file described above are not required for
the successful creation of the `VRTAutoClientManager` utility, only for creating
Actions from these sources.
