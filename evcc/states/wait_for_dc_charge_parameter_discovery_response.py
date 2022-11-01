"""
.. module:: wait_for_dc_charge_parameter_discovery_response
   :platform: Unix
   :synopsis: A module describing the DcChargeParameterDiscovery state.

.. Copyright 2022 EDF 

.. moduleauthor:: Oscar RODRIGUEZ INFANTE, Tony ZHOU, Trang PHAM, Efflam OLLIVIER 

.. License:: This source code is licensed under the MIT License.


"""

from evcc.states.ev_state import DcEVState
from shared.reaction_message import ReactionToIncomingMessage, SendMessage
import time, os

from shared.xml_classes.common_messages import ScheduleExchangeReq
from shared.xml_classes.iam import AttestationReq, MessageHeaderType

IAM_NONCE_SIZE=8 # TODO: Figure out where to put this

class WaitForDcChargeParameterDiscoveryResponse(DcEVState):
    def __init__(self):
        super(WaitForDcChargeParameterDiscoveryResponse, self).__init__(name="WaitForDcChargeParameterDiscoveryRes")

    def process_payload(self, payload) -> ReactionToIncomingMessage:
        evse_data = payload.bpt_dc_cpdres_energy_transfer_mode
        self.controller.data_model.evsemaximum_charge_power = evse_data.evsemaximum_charge_power
        self.controller.data_model.evsemaximum_discharge_power = evse_data.evsemaximum_discharge_power
        # TODO: handle evse data, only max power is handled now for the hmi

        extra_data = {}
        reaction = SendMessage()
        if self.controller.data_model.using_IAM:
            request = AttestationReq()
            self.controller.data_model.challenge_nonce = os.urandom(8)
            request.challenge_nonce = self.controller.data_model.challenge_nonce
            reaction.msg_type = "IAM"
        else:
            request = ScheduleExchangeReq()
            request.maximum_supporting_points = 1024
            request.dynamic_sereq_control_mode = self.controller.data_model.get_dynamic_sereq_control_mode()
            reaction.msg_type = "Common"

        request.header = MessageHeaderType(self.session_parameters.session_id, int(time.time()))
        
        reaction.message = request
        reaction.extra_data = extra_data
        
        return reaction
