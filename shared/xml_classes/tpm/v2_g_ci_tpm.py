from dataclasses import dataclass, field
from typing import Optional
from shared.xml_classes.iam.v2_g_ci_common_types import (
    V2GrequestType,
    V2GresponseType,
)
from shared.xml_classes.common_messages.v2_g_ci_common_messages import (ServiceIdlistType)

__NAMESPACE__ = "urn:iso:std:iso:15118:-20:TPMMessages"


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
            "name": "SupportedServiceIDs",
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:CommonMessages",
        }
    )
    mandatory_if_mutally_supported_service_ids: Optional[ServiceIdlistType] = field(
        default=None,
        metadata={
            "name": "SupportedServiceIDs",
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:CommonMessages",
        }
    )


@dataclass
class SeccCapabilityChallengeResType(V2GresponseType):
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
    challenge_evidence: Optional[bytes] = field( # TODO
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "length": 8,
            "format": "base16",
        }
    )

@dataclass
class EvccCapabilityChallengeReqType(V2GrequestType):
    challenge_evidence: Optional[bytes] = field( # TODO
        default=None,
        metadata={
            "type": "Element",
            "namespace": "urn:iso:std:iso:15118:-20:TPMMessages",
            "required": True,
            "length": 8,
            "format": "base16",
        }
    )

@dataclass
class EvccCapabilityChallengeResType(V2GrequestType):
    supported_app_protocol_chosen_schema_id: Optional[int] = field(
        default=None,
        metadata={
            "name": "SchemaID",
            "type": "Element",
            "namespace": "",
            "required": True,
        }
    )

@dataclass
class SeccCapabilityChallengeReq(SeccCapabilityChallengeReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"

@dataclass
class SeccCapabilityChallengeRes(SeccCapabilityChallengeResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"


@dataclass
class EvccCapabilityChallengeReq(EvccCapabilityChallengeReqType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"

@dataclass
class EvccCapabilityChallengeRes(EvccCapabilityChallengeResType):
    class Meta:
        namespace = "urn:iso:std:iso:15118:-20:TPMMessages"
