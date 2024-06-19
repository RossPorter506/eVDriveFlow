"""
.. module:: process_capability_challenge_request
   :platform: Unix
   :synopsis: A module describing the SECC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.tpm import CapabilityChallengeRes, MessageHeaderType, ResponseCodeType
from shared.global_values import CAPABILITY_NONCE_SIZE
from tests.timer import validation_timer
from shared.log import logger

from hashlib import sha256
import time, os, subprocess
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

class ProcessCapabilityChallengeRequest(EVSEState):
    def __init__(self):
        super(ProcessCapabilityChallengeRequest, self).__init__(name="ProcessCapabilityChallengeReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        #validation_timer.start()
        self._tpm_start_attesting_contents(payload.challenge_nonce)
        #validation_timer.pause()
        extra_data = {}
        response = CapabilityChallengeRes()
        
        self.controller.data_model.evcc_challenge_nonce = os.urandom(CAPABILITY_NONCE_SIZE)
        response.challenge_nonce = self.controller.data_model.evcc_challenge_nonce
        response.supported_app_protocol_chosen_schema_id = self.controller.data_model.chosen_schema_id
        
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "TPM"
        return reaction

    def _tpm_start_attesting_contents(self, nonce: bytes):
        self.controller.data_model.quote_process = subprocess.Popen(["bash", "../TPM/secc/SECC_runtime.sh", nonce.hex()])
        #self.controller.data_model.quote_process.wait()

