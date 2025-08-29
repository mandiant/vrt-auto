# Candidates

## AbstractFileCandidate

| Attribute        | Type                    | Prepopulated Value                            | Description                                                                                             |
|------------------|-------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------|
| file_hash        | str                     |                                               | The hash of the file, used for confirming correct file upload and identifying the file on the director. |
| file_bytes       | bytes                   | This is an Action created using VRT Auto.     | The actual file to be uploaded, represented as bytes.                                                   |
| file_name        | str                     | AbstractFileCandidate_{UUID4}                 | The name assigned to the file when uploaded to the file library.                                        |
| file_description | str                     | AbstractFileCandidate Description Placeholder | The description for the file when uploaded to the file library.                                         |
| operating_system | OSPlatformDimensionEnum | GENERAL_OS_PLATFORM                           | An instance of OSPlatformDimensionEnum, for use in assigning the file an OS in the file library.        |
| user_tags        | list[str]               | ["VRT_AUTO"]                                  | A list of tags to apply to the created file.                                                            |

## AbstractActionCandidate

| Attribute                  | Type      | Prepopulated Value                        | Description                                                     |
|----------------------------|-----------|-------------------------------------------|-----------------------------------------------------------------|
| action_title               | str       | (VRT Auto) - {UUID4}                      | The title of the Action.                                        |
| action_description         | str       | This is an Action created using VRT Auto. | The description of the Action.                                  |
| user_tags                  | list[str] | ["VRT_AUTO"]                              | A list of tags to apply to the created Action.                  |
| user_run_as_tags           | list[str] |                                           | A list of run_as tags to apply to the created Action.           |
| user_src_dst_tags          | list[str] |                                           | A list of src_dst tags to apply to the created Action.          |
| user_os_tags               | list[str] |                                           | A list of os tags to apply to the created Action.               |
| user_control_tags          | list[str] |                                           | A list of control tags to apply to the created Action.          |
| user_mitre_mitigation_tags | list[str] |                                           | A list of mitre mitigation tags to apply to the created Action. |
| user_nist_control_tags     | list[str] |                                           | A list of nist control tags to apply to the created Action.     |

### AbstractMFTActionCandidate

| Attribute                  | Type                  | Prepopulated Value                        | Description                                                                                   |
|----------------------------|-----------------------|-------------------------------------------|-----------------------------------------------------------------------------------------------|
| action_title               | str                   | File Transfer (VRT Auto) - {UUID4}        | _(Attributes described above will not be repeated)_                                           |
| action_description         | str                   | This is an Action created using VRT Auto. |                                                                                               |
| user_tags                  | list[str]             | ["VRT_AUTO"]                              |                                                                                               |
| user_run_as_tags           | list[str]             |                                           |                                                                                               |
| user_src_dst_tags          | list[str]             |                                           |                                                                                               |
| user_os_tags               | list[str]             | ["OS:ANY"]                                |                                                                                               |
| user_control_tags          | list[str]             |                                           |                                                                                               |
| user_mitre_mitigation_tags | list[str]             |                                           |                                                                                               |
| user_nist_control_tags     | list[str]             |                                           |                                                                                               |
| file_target                | AbstractFileCandidate |                                           | An instance of an AbstractFileCandidate subclass containing a file to use for the MFT Action. |

### AbstractDNSActionCandidate

| Attribute                  | Type      | Prepopulated Value                        | Description                                                                                                    |
|----------------------------|-----------|-------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| action_title               | str       | DNS Query (VRT Auto) - {UUID4}            |                                                                                                                |
| action_description         | str       | This is an Action created using VRT Auto. |                                                                                                                |
| user_tags                  | list[str] | ["VRT_AUTO", "ATT&CK:T1071.004"]          |                                                                                                                |
| user_run_as_tags           | list[str] |                                           |                                                                                                                |
| user_src_dst_tags          | list[str] |                                           |                                                                                                                |
| user_os_tags               | list[str] | ["OS:ANY"]                                |                                                                                                                |
| user_control_tags          | list[str] |                                           |                                                                                                                |
| user_mitre_mitigation_tags | list[str] |                                           |                                                                                                                |
| user_nist_control_tags     | list[str] |                                           |                                                                                                                |
| domain                     | str       |                                           | A domain to query in the Action. Can be defanged with `hxxp` and `[.]`, will be fanged during Action creation. |

### AbstractEmailNoAttachmentActionCandidate

| Attribute                  | Type      | Prepopulated Value                         | Description                                                                                                                                                 |
|----------------------------|-----------|--------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| action_title               | str       | Email (No Attachment) (VRT Auto) - {UUID4} |                                                                                                                                                             |
| action_description         | str       | This is an Action created using VRT Auto.  |                                                                                                                                                             |
| user_tags                  | list[str] | ["VRT_AUTO"]                               |                                                                                                                                                             |
| user_run_as_tags           | list[str] |                                            |                                                                                                                                                             |
| user_src_dst_tags          | list[str] |                                            |                                                                                                                                                             |
| user_os_tags               | list[str] | ["OS:ANY"]                                 |                                                                                                                                                             |
| user_control_tags          | list[str] | ["Control:EMAIL"]                          |                                                                                                                                                             |
| user_mitre_mitigation_tags | list[str] |                                            |                                                                                                                                                             |
| user_nist_control_tags     | list[str] |                                            |                                                                                                                                                             |
| body                       | str       |                                            | The body of the email. Assumed to contain a malicious link, but not enforced. Can be defanged with `hxxp` and `[.]`, will be fanged during Action creation. |

### AbstractEmailAttachmentActionCandidate

| Attribute                  | Type                  | Prepopulated Value                        | Description                                                                                     |
|----------------------------|-----------------------|-------------------------------------------|-------------------------------------------------------------------------------------------------|
| action_title               | str                   | Email (Attachment) (VRT Auto) - {UUID4}   |                                                                                                 |
| action_description         | str                   | This is an Action created using VRT Auto. |                                                                                                 |
| user_tags                  | list[str]             | ["VRT_AUTO"]                              |                                                                                                 |
| user_run_as_tags           | list[str]             |                                           |                                                                                                 |
| user_src_dst_tags          | list[str]             |                                           |                                                                                                 |
| user_os_tags               | list[str]             | ["OS:ANY"]                                |                                                                                                 |
| user_control_tags          | list[str]             | ["Control:EMAIL"]                         |                                                                                                 |
| user_mitre_mitigation_tags | list[str]             |                                           |                                                                                                 |
| user_nist_control_tags     | list[str]             |                                           |                                                                                                 |
| body                       | str                   | Placeholder                               | The body of the email. Not required for Actions with file attachments.                          |
| file_target                | AbstractFileCandidate |                                           | An instance of an AbstractFileCandidate subclass containing a file to use for the Email Action. |

### AbstractProtectedTheaterFileActionCandidate

| Attribute                  | Type                  | Prepopulated Value                        | Description                                                                                           |
|----------------------------|-----------------------|-------------------------------------------|-------------------------------------------------------------------------------------------------------|
| action_title               | str                   | Protected Theater (VRT Auto) - {UUID4}    |                                                                                                       |
| action_description         | str                   | This is an Action created using VRT Auto. |                                                                                                       |
| user_tags                  | list[str]             | ["VRT_AUTO"]                              |                                                                                                       |
| user_run_as_tags           | list[str]             |                                           |                                                                                                       |
| user_src_dst_tags          | list[str]             |                                           |                                                                                                       |
| user_os_tags               | list[str]             | ["OS:ANY"]                                |                                                                                                       |
| user_control_tags          | list[str]             | ["Control:EMAIL"]                         |                                                                                                       |
| user_mitre_mitigation_tags | list[str]             |                                           |                                                                                                       |
| user_nist_control_tags     | list[str]             |                                           |                                                                                                       |
| file_target                | AbstractFileCandidate |                                           | An instance of an AbstractFileCandidate subclass containing a file to use for the PT Action.          |
| factory                    | HostActionFactory     |                                           | A HostActionFactory object. Expected to be configured by the Candidate for PT Action creation.        |
| action_file_path           | str                   | C:\\Users\\Public\\Documents\\            | The file path to place the file during the PT Action. Used to configure the HostActionFactory object. |
| action_file_name           | str                   |                                           | The file name to give the file during the PT Action.  Used to configure the HostActionFactory object. |


