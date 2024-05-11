"""
.. module:: process_secc_capability_challenge_request
   :platform: Unix
   :synopsis: A module describing the SECC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.tpm import SeccCapabilityChallengeRes, MessageHeaderType, ResponseCodeType
from shared.global_values import CAPABILITY_NONCE_SIZE
from tests.timer import attestation_timer
from shared.log import logger

from hashlib import sha256
import time, os

class ProcessSeccCapabilityChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessSeccCapabilityChallengeRequest, self).__init__(name="ProcessSeccCapabilityChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        extra_data = {}
        response = SeccCapabilityChallengeRes()
        #attestation_timer.start()
        #(response.evidence, response.signature) = hash_sign_secc_software(payload.challenge_nonce.hex())
        response.challenge_signature = self._get_tpm_signature(payload.challenge_nonce)
        response.challenge_evidence = self._get_tpm_evidence()
        
        self.controller.data_model.evcc_challenge_nonce = os.urandom(CAPABILITY_NONCE_SIZE)
        response.challenge_nonce = self.controller.data_model.evcc_challenge_nonce
        
        #atime = attestation_timer.stop()
        #with open("../attestation.txt", 'a') as f:
        #    f.write(str(atime)+'\n')
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "TPM"
        return reaction
    
    def _get_tpm_signature(self, nonce: bytes):
        logger.warn("Used stubbed TPM signature")
        return os.urandom(64) # TODO
    
    def _get_tpm_evidence(self):
        logger.warn("Used stubbed TPM evidence")
        return self.controller.data_model.secc_tpm_evidence # TODO
