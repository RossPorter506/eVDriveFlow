from dataclasses import dataclass, field
from typing import Optional
from shared.xml_classes.iam.v2_g_ci_common_types import (
    V2GrequestType,
    V2GresponseType,
)

__NAMESPACE__ = "urn:iso:std:iso:15118:-20:IAMMessages"


@dataclass
class AttestationChallengeReqType(V2GrequestType):
    challenge_nonce: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 8,
            "format": "base16",
        }
    )


@dataclass
class AttestationChallengeResType(V2GresponseType):
    challenge_nonce: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 8,
            "format": "base16",
        }
    )


@dataclass
class AttestationEvidenceReqType(V2GrequestType):
    evidence: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 32,
            "format": "base16",
        }
    )
    signature: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 64,
            "format": "base16",
        }
    )


@dataclass
class AttestationEvidenceResType(V2GresponseType):
    evidence: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 32,
            "format": "base16",
        }
    )
    signature: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 64,
            "format": "base16",
        }
    )


@dataclass
class AttestationChallengeReq(AttestationChallengeReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"


@dataclass
class AttestationChallengeRes(AttestationChallengeResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"


@dataclass
class AttestationEvidenceReq(AttestationEvidenceReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"


@dataclass
class AttestationEvidenceRes(AttestationEvidenceResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"
