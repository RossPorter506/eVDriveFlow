from dataclasses import dataclass, field
from typing import Optional
from shared.xml_classes.iam.v2_g_ci_common_types import (
    V2GrequestType,
    V2GresponseType,
)

__NAMESPACE__ = "urn:iso:std:iso:15118:-20:IAMMessages"


@dataclass
class AttestationReqType(V2GrequestType):
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
class AttestationResType(V2GresponseType):
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
class AttestationReq(AttestationReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"


@dataclass
class AttestationRes(AttestationResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"
