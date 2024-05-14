from dataclasses import dataclass, field
from typing import Optional
from shared.xml_classes.tpm.v2_g_ci_common_types import (
    ServiceIdlistType,
    V2GrequestType,
    V2GresponseType,
)

__NAMESPACE__ = "urn:iso:std:iso:15118:-20:TPMMessages"


@dataclass
class EvccCapabilityChallengeReqType(V2GrequestType):
    challenge_evidence: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "max_length": 256,
            "format": "base16",
        }
    )
    challenge_signature: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "length": 64,
            "format": "base16",
        }
    )


@dataclass
class EvccCapabilityChallengeResType(V2GresponseType):
    supported_app_protocol_chosen_schema_id: Optional[int] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
        }
    )


@dataclass
class SeccCapabilityChallengeReqType(V2GrequestType):
    challenge_nonce: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "length": 8,
            "format": "base16",
        }
    )
    supported_service_ids: Optional[ServiceIdlistType] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
        }
    )
    mandatory_if_mutally_supported_service_ids: Optional[ServiceIdlistType] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
        }
    )


@dataclass
class SeccCapabilityChallengeResType(V2GrequestType):
    challenge_nonce: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "length": 8,
            "format": "base16",
        }
    )
    challenge_evidence: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "max_length": 256,
            "format": "base16",
        }
    )
    challenge_signature: Optional[bytes] = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "length": 64,
            "format": "base16",
        }
    )


@dataclass
class EvccCapabilityChallengeReq(EvccCapabilityChallengeReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"


@dataclass
class EvccCapabilityChallengeRes(EvccCapabilityChallengeResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"


@dataclass
class SeccCapabilityChallengeReq(SeccCapabilityChallengeReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"


@dataclass
class SeccCapabilityChallengeRes(SeccCapabilityChallengeResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"
