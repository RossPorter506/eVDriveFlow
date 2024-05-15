"""
.. module:: wait_for_capability_attestation_secc_response
   :platform: Unix
   :synopsis: A module describing the SECC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import SessionStopReq, MessageHeaderType, ChargingSessionType
from shared.xml_classes.tpm import SeccCapabilityChallengeReq, EvccCapabilityChallengeReq
from shared.xml_classes.tpm import MessageHeaderType as TpmMessageHeaderType
from shared.log import logger

import os, subprocess

from hashlib import sha256
from ecdsa import VerifyingKey, BadSignatureError
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

class WaitForSeccCapabilityChallengeResponse(DcEVState):
    def __init__(self):
        super(WaitForSeccCapabilityChallengeResponse, self).__init__(name="WaitForSeccCapabilityChallengeRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        reaction = SendMessage()
        if payload.challenge_evidence and payload.challenge_signature \
        and self._verify(payload.challenge_signature, payload.challenge_evidence, self.controller.data_model.secc_challenge_nonce):
            # Hash matches sig. We don't know if hash is good until we can inspect the services during ServiceDetail. Continue for now.
            self.controller.data_model.secc_tpm_evidence = payload.challenge_evidence
            logger.info('SECC Capability Attestation Successful so far. Continuing to EVCC capability attestation.')
            request = EvccCapabilityChallengeReq()
            
            self._tpm_attest_contents(payload.challenge_nonce)
            request.challenge_evidence = self._get_tpm_evidence()
            request.challenge_signature = self._get_tpm_signature()
            request.header = TpmMessageHeaderType(self.session_parameters.session_id, int(time.time()))
            reaction.msg_type = "TPM"

        else: # attestation failed - SECC possibly compromised
            logger.warn('SECC capability attestation failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "SECC capability attestation failure"
            request.evtermination_explanation = "Failure during SECC capability attestation"
            reaction.msg_type = "Common"
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        
        reaction.message = request
        extra_data = {}
        reaction.extra_data = extra_data
        return reaction

    def _verify(self, sig: bytes, message: bytes, nonce: bytes) -> bool:
        r = int.from_bytes(sig[0:32], "big")
        s = int.from_bytes(sig[32:64], "big")
        sig_der = encode_dss_signature(int(r), int(s))
        
        open("sig_file", 'wb').write(sig_der)
        open("message_file", 'wb').write(message)
        
        try:
            subprocess.check_output(["tpm2_checkquote", \
                "-u", "../TPM/secc/secc_sign_public_key.pem", \
                "-g", "sha256", \
                "-m", "message_file", \
                "-s", "sig_file", \
                "-q", nonce.hex()])
        except subprocess.CalledProcessError as e:
            logger.warn("Signature verification failed:" + str(e))
            return False
        
        return True

    def _tpm_attest_contents(self, nonce: bytes):
        subprocess.run(["bash", "../TPM/evcc/EVCC_runtime.sh", nonce.hex()])

    def _get_tpm_signature(self) -> bool:
        signature_der = open("../TPM/evcc/ecc_signature.der", 'rb').read()
        
        (r, s) = decode_dss_signature(signature_der)
        signature_p1363 = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        return signature_p1363

    def _get_tpm_evidence(self) -> bool:
        return open("../TPM/evcc/attestation.nv_cert_info", 'rb').read()
