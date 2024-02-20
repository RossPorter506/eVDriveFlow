"""
.. module:: process_service_detail_request
   :platform: Unix
   :synopsis: A module describing the ServiceDetail state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER 

.. License:: This source code is licensed under the MIT License.


"""

from .evse_state import EVSEState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType
from shared.xml_classes.iam import AttestationRes, MessageHeaderType
import time

from ecdsa import SigningKey
from IAM.IAM_TEE import hash_sign_secc_software
from tests.timer import attestation_timer

class ProcessAttestationRequest(EVSEState):
    def __init__(self):
        super(ProcessAttestationRequest, self).__init__(name="ProcessAttestationReq")
        with open("../shared/certificates/IAM_keys/secc_private_attestation_key.pem", "r") as secure_key_file:
            self.secc_secure_key = SigningKey.from_pem(secure_key_file.read()) # In practise this key should not be accessible outside the TPM.

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        
        extra_data = {}
        response = AttestationRes()
        attestation_timer.start()
        (response.evidence, response.signature) = hash_sign_secc_software(payload.challenge_nonce.hex())
        atime = attestation_timer.stop()
        with open("../attestation.txt", 'a') as f:
            f.write(str(atime)+'\n')
        response.response_code = ResponseCodeType.OK
        response.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.extra_data = extra_data
        reaction.message = response
        reaction.msg_type = "IAM"
        return reaction
