"""
.. module:: wait_for_capability_challenge_response
   :platform: Unix
   :synopsis: A module describing the SECC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import SessionStopReq, MessageHeaderType, ChargingSessionType, SessionSetupReq
from shared.xml_classes.tpm import CapabilityChallengeReq
from shared.xml_classes.tpm import MessageHeaderType as TpmMessageHeaderType
from shared.log import logger
from tests.timer import validation_timer

import os, subprocess

from hashlib import sha256
from ecdsa import VerifyingKey, BadSignatureError
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

class WaitForCapabilityChallengeResponse(DcEVState):
    def __init__(self):
        super(WaitForCapabilityChallengeResponse, self).__init__(name="WaitForCapabilityChallengeRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        reaction = SendMessage()
        validation_timer.start()
        self._tpm_start_attesting_contents(payload.challenge_nonce)
        request = SessionSetupReq()
        session_id = "00000000".encode("ascii")
        request.evccid = self.controller.data_model.evccid
        request.header = MessageHeaderType(session_id, int(time.time()))
        reaction.message = request
        reaction.msg_type = "Common"
        extra_data = {}
        reaction.extra_data = extra_data
        return reaction

    def _tpm_start_attesting_contents(self, nonce: bytes):
        self.controller.data_model.quote_process = subprocess.Popen(["bash", "../TPM/evcc/EVCC_runtime.sh", nonce.hex()])
        #self.controller.data_model.quote_process.wait()


