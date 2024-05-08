"""
.. module:: process_evcc_capability_challenge_request
   :platform: Unix
   :synopsis: A module describing the EVCC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.tpm import EvccCapabilityChallengeRes, MessageHeaderType
from shared.global_values import CAPABILITY_NONCE_SIZE

import time

from ecdsa import SigningKey
from tests.timer import attestation_timer

class ProcessEvccCapabilityChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessSeccCapabilityChallengeRequest, self).__init__(name="ProcessSeccCapabilityChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        
        extra_data = {}
        response = EvccCapabilityChallengeRes()
        response.supported_app_protocol_chosen_schema_id = self.controller.data_model.chosen_schema_id
        if self._verify_evcc_cert(payload.challenge_nonce):
            response.response_code = ResponseCodeType.OK
        else:
            response.response_code = ResponseCodeType.FAILED
        
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "TPM"
        return reaction
    
    def _verify_evcc_cert(nonce: bytes):
        return True #TODO
