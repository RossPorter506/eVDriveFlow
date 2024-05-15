"""
.. module:: wait_for_capability_attestation_evcc_response
   :platform: Unix
   :synopsis: A module describing the EVCC Capability Challenge state.

.. Copyright 2022 EDF 

.. moduleauthor:: Ross PORTER

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import SessionStopReq, MessageHeaderType, ChargingSessionType, SessionSetupReq
from shared.xml_classes.tpm import ResponseCodeType
from shared.log import logger

import time
from ecdsa import VerifyingKey, BadSignatureError

class WaitForEvccCapabilityChallengeResponse(DcEVState):
    def __init__(self):
        super(WaitForEvccCapabilityChallengeResponse, self).__init__(name="WaitForEvccCapabilityChallengeRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        reaction = SendMessage()
        if payload.response_code == ResponseCodeType.OK:
            # SECC was happy with our evidence
            logger.info('EVCC Capability Attestation Successful. Continuing to Session Setup.')
            request = SessionSetupReq()
            session_id = "00000000".encode("ascii")
            request.evccid = self.controller.data_model.evccid
            request.header = MessageHeaderType(session_id, int(time.time()))

        else: # attestation failed - EVCC possibly compromised
            logger.warn('EVCC capability attestation failed. Ending session.')
            self.controller.stop() # Signal rest of system to wind down
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            # message vague on purpose. We probably shouldn't mention attestation at all.
            request.evtermination_code = "SECC capability attestation failure"
            request.evtermination_explanation = "Failure during SECC capability attestation"
        
        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        reaction.msg_type = "Common"
        reaction.message = request
        extra_data = {}
        reaction.extra_data = extra_data
        return reaction
