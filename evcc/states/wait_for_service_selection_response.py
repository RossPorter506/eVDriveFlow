"""
.. module:: wait_for_service_selection_response
   :platform: Unix
   :synopsis: A module describing the ServiceSelection state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER 

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import EVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
from shared.xml_classes.common_messages import ResponseCodeType, SessionStopReq, ChargingSessionType
from shared.xml_classes.dc import MessageHeaderType
import time
from shared.xml_classes.dc import DcChargeParameterDiscoveryReq


class WaitForServiceSelectionResponse(EVState):
    def __init__(self):
        super(WaitForServiceSelectionResponse, self).__init__(name="WaitForServiceSelectionRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        if payload.response_code == ResponseCodeType.FAILED:
            self.controller.stop()
            request = SessionStopReq()
            request.charging_session = ChargingSessionType.TERMINATE
            # We probably shouldn't mention attestation at all.
            request.evtermination_code = "Failure during service selection"
            request.evtermination_explanation = "Failure during service selection"
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
            reaction = SendMessage()
            reaction.extra_data = {}
            reaction.message = request
            reaction.msg_type = "Common"
            return reaction
        else:
            extra_data = {}
            request = DcChargeParameterDiscoveryReq()
            request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
            # TODO: test based on service selected
            request.bpt_dc_cpdreq_energy_transfer_mode = self.controller.data_model.get_bpt_dc_cpdreq_energy_transfer_mode()
            reaction = SendMessage()
            reaction.extra_data = extra_data
            reaction.message = request
            reaction.msg_type = "DC"
            return reaction
