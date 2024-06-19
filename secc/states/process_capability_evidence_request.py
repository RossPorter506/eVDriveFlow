"""
.. module:: process_capability_evidence_request
   :platform: Unix
   :synopsis: A module describing the EVCC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.tpm import CapabilityEvidenceRes, MessageHeaderType
from shared.global_values import CAPABILITY_NONCE_SIZE
from shared.log import logger
from shared.tpm import _parse_and_check_tpms_attest_cert
from tests.timer import validation_timer

import time, subprocess

from ecdsa import SigningKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from hashlib import sha256

class ProcessCapabilityEvidenceRequest(EVSEState):
    def __init__(self):
        super(ProcessCapabilityEvidenceRequest, self).__init__(name="ProcessCapabilityEvidenceReq")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        
        extra_data = {}
        response = CapabilityEvidenceRes()
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.msg_type = "TPM"
        
        self.controller.data_model.evcc_supported_service_ids = payload.supported_service_ids
        self.controller.data_model.evcc_mandatory_if_mutually_supported_service_ids = payload.mandatory_if_mutally_supported_service_ids
        #validation_timer.resume()
        calculated_hash = self.calculate_evcc_hash_from_evidence()
        structure_ok = _parse_and_check_tpms_attest_cert(payload.challenge_evidence, self.controller.data_model.evcc_challenge_nonce, calculated_hash)
        if structure_ok:
            self.controller.data_model.quote_process.wait()
            value_ok = self._verify_evcc_signature(payload.challenge_signature, payload.challenge_evidence, self.controller.data_model.evcc_challenge_nonce)
            if value_ok:
                response.response_code = ResponseCodeType.OK
                logger.info("EVCC Verified")
        if not (structure_ok and value_ok):
            response.response_code = ResponseCodeType.FAILED
            logger.warn("EVCC Not Verified")
        #validation_timer.pause()
        
        self.controller.data_model.quote_process.wait()
        response.challenge_signature = self._get_tpm_signature()
        response.challenge_evidence = self._get_tpm_evidence()
        
        reaction.message = response
        return reaction
    
    def _verify_evcc_signature(self, sig: bytes, message: bytes, nonce: bytes) -> bool:
        r = int.from_bytes(sig[0:32], "big")
        s = int.from_bytes(sig[32:64], "big")
        print("@@@@", r,s)
        sig_der = encode_dss_signature(r, s)
        
        open("sig_file", 'wb').write(sig_der)
        open("message_file", 'wb').write(message)
        
        try:
            subprocess.check_output(["tpm2_checkquote", \
                "-u", "../TPM/evcc/evcc_sign_public_key.pem", \
                "-g", "sha256", \
                "-m", "message_file", \
                "-s", "sig_file", \
                "-q", nonce.hex()])
        except subprocess.CalledProcessError as e:
            logger.warn("Signature verification failed:" + str(e))
            return False
        
        return True
    
    def calculate_evcc_hash_from_evidence(self) -> str:
        self.controller.data_model.evcc_supported_service_ids.service_id.sort()
        supported_services = bytearray()
        for service_id in self.controller.data_model.evcc_supported_service_ids.service_id:
            print("ID:", service_id)
            supported_services += service_id.to_bytes(2, "big")
        print(supported_services)
        
        MiMS_services = bytearray()
        self.controller.data_model.evcc_mandatory_if_mutually_supported_service_ids.service_id.sort()
        for service_id in self.controller.data_model.evcc_mandatory_if_mutually_supported_service_ids.service_id:
            print("MID:", service_id)
            MiMS_services += service_id.to_bytes(2, "big")
        print(MiMS_services)
        
        supported_app_protocols = bytearray()
        self.controller.data_model.evcc_supported_app_protocols.sort(key = lambda a: a.protocol_namespace)
        for protocol in self.controller.data_model.evcc_supported_app_protocols:
            print("APP:", protocol)
            supported_app_protocols += bytearray(protocol.protocol_namespace.encode("UTF-8"))
            supported_app_protocols += protocol.version_number_major.to_bytes(4, "big")
            supported_app_protocols += protocol.version_number_minor.to_bytes(4, "big")
        print(supported_app_protocols)
        
        hsh = sha256(supported_services + MiMS_services + supported_app_protocols).hexdigest()
        print(hsh)
        return hsh

    def _get_tpm_signature(self) -> bool:
        signature_der = open("../TPM/secc/ecc_signature.der", 'rb').read()
        
        (r, s) = decode_dss_signature(signature_der)
        signature_p1363 = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        return signature_p1363

    def _get_tpm_evidence(self) -> bool:
        return open("../TPM/secc/attestation.nv_cert_info", 'rb').read()
