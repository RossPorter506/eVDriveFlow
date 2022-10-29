from dataclasses import dataclass, field
from typing import List, Optional
from shared.xml_classes.common_messages.v2_g_ci_common_types import (
    V2GrequestType,
    V2GresponseType,
)
from shared.xml_classes.common_messages.v2_g_ci_common_messages import (ScheduleExchangeReqType, DynamicSereqControlModeType, ScheduledSereqControlModeType)


@dataclass
class AttestationReqType(V2GrequestType):
    # NOTE: You absolutely CANNOT name this field 'nonce', otherwise the XML Serializer will crash with: "Unknown format 'None'".
    challenge_nonce: Optional[bytes] = field( 
        default=None,
        metadata={
            "name": "challenge_nonce",
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 8, # 8-byte nonce
            "format": "base16",
        }
    )


@dataclass
class AttestationResType(V2GresponseType):
    evidence: Optional[bytes] = field(
        default=None,
        metadata={
            "name": "evidence",
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 40, # 8-byte nonce + 32-byte hash
            "format": "base16",
        }
    )
    signature: Optional[bytes] = field(
        default=None,
        metadata={
            "name": "signature",
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:IAMMessages",
            "required": True,
            "length": 48,
            "format": "base16",
        }
    )

@dataclass
class AttestationRes(AttestationResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"

@dataclass
class AttestationReq(AttestationReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:IAMMessages"