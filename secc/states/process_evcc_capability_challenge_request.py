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
from shared.log import logger

import time

from ecdsa import SigningKey
from tests.timer import attestation_timer
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

class ProcessEvccCapabilityChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessEvccCapabilityChallengeRequest, self).__init__(name="ProcessEvccCapabilityChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        
        extra_data = {}
        response = EvccCapabilityChallengeRes()
        response.supported_app_protocol_chosen_schema_id = self.controller.data_model.chosen_schema_id
        if self._verify_evcc_signature(payload.challenge_signature, payload.challenge_evidence, self.controller.data_model.evcc_challenge_nonce):
            response.response_code = ResponseCodeType.OK
            logger.info("EVCC Verified")
        else:
            response.response_code = ResponseCodeType.FAILED
            logger.warn("EVCC Not Verified")
        
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "TPM"
        return reaction
    
    def _verify_evcc_signature(self, sig: bytes, message: bytes, nonce: bytes):
        r = sig[0:32]
        s = sig[32:64]
        sig_der = encode_dss_signature(r, s)
        
        open("sig_file", 'wb').write(sig_der)
        open("message_file", 'wb').write(message)
        
        try:
            subprocess.check_output(["tpm2_check_quote", \
                "-u", "../TPM/evcc/evcc_sign_public_key.pem", \
                "-g", "sha256", \
                "-m", "message_file", \
                "-s", "sig_file", \
                "-q", nonce.hex()])
        except CalledProcessError as e:
            logger.warn("Signature verification failed:" + str(e))
            return False
        
        return True
