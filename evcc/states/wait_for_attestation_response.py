"""
.. module:: wait_for_attestation_response
   :platform: Unix
   :synopsis: A module describing the Attestation state (for IAM).

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time
from shared.xml_classes.common_messages import ScheduleExchangeReq, SessionStopReq, MessageHeaderType, ChargingSessionType
from shared.log import logger

from ecdsa import VerifyingKey, BadSignatureError

class WaitForAttestationResponse(DcEVState):
    def __init__(self):
        super(WaitForAttestationResponse, self).__init__(name="WaitForAttestationRes")
        with open("../shared/certificates/IAM_keys/secc_public_key.pem", "r") as pub_key_file:
            self.secc_public_key = VerifyingKey.from_pem(pub_key_file.read())

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        if payload.evidence and payload.signature \
            and self._verify(payload.evidence, payload.signature): #attestation success, continue to schedule exchange
            logger.info('Attestation Successful. Continuing session.')

            request = ScheduleExchangeReq()
            evse_data = payload.bpt_dc_cpdres_energy_transfer_mode
            request.dynamic_sereq_control_mode = self.controller.data_model.get_dynamic_sereq_control_mode()
            self.controller.data_model.evsemaximum_charge_power = evse_data.evsemaximum_charge_power
            self.controller.data_model.evsemaximum_discharge_power = evse_data.evsemaximum_discharge_power
            request.maximum_supporting_points = 1024
            # TODO: handle evse data, only max power is handled now for the hmi
        else: # attestation failed - SECC possibly compromised
            logger.warn('Attestation Failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE

            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "Attestation Failure"
            request.evtermination_explanation = "Failure during attestation" 
        
        extra_data = {}
        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction = SendMessage()
        reaction.message = request
        reaction.extra_data = extra_data
        reaction.msg_type = "Common"
        return reaction

    def _verify(self, message: bytes, sig: bytes) -> bool:
        try:
            signature_correct = self.secc_public_key.verify(sig, message)
        except BadSignatureError:
            signature_correct = False
        
        nonce = message[:8]
        hsh = message[8:]

        nonce_correct = (nonce == self.controller.data_model.provided_nonce)
        hash_correct = True #(hsh == self.controller.data_model.expected_hash) # TODO: Generate expected hash

        return all([signature_correct, nonce_correct, hash_correct])
    