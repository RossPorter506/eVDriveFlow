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
from tests.timer import validation_timer
from shared.log import logger

from hashlib import sha256
import time, os, subprocess
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

class ProcessSeccCapabilityChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessSeccCapabilityChallengeRequest, self).__init__(name="ProcessSeccCapabilityChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        extra_data = {}
        response = SeccCapabilityChallengeRes()
        validation_timer.start()
        before_quote_time = validation_timer.lap()
        self._tpm_attest_contents(payload.challenge_nonce)
        quote_time = validation_timer.lap()
        response.challenge_signature = self._get_tpm_signature()
        response.challenge_evidence = self._get_tpm_evidence()
        attest_time = validation_timer.lap()
        validation_timer.pause()
        with open("before_quote_time.txt", 'a') as f:
                f.write(str(before_quote_time)+'\n')
        with open("certify_time.txt", 'a') as f:
                f.write(str(attest_time)+'\n')
        with open("quote_time.txt", 'a') as f:
                f.write(str(quote_time)+'\n')
        
        self.controller.data_model.evcc_supported_service_ids = payload.supported_service_ids
        self.controller.data_model.evcc_mandatory_if_mutually_supported_service_ids = payload.mandatory_if_mutally_supported_service_ids
        self.controller.data_model.evcc_challenge_nonce = os.urandom(CAPABILITY_NONCE_SIZE)
        
        response.challenge_nonce = self.controller.data_model.evcc_challenge_nonce
        
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "TPM"
        return reaction

    def _tpm_attest_contents(self, nonce: bytes):
        subprocess.run(["bash", "../TPM/secc/SECC_runtime.sh", nonce.hex()])

    def _get_tpm_signature(self) -> bool:
        signature_der = open("../TPM/secc/ecc_signature.der", 'rb').read()
        
        (r, s) = decode_dss_signature(signature_der)
        signature_p1363 = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        return signature_p1363

    def _get_tpm_evidence(self) -> bool:
        return open("../TPM/secc/attestation.nv_cert_info", 'rb').read()
