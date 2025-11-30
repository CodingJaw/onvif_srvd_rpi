#include "soapDeviceIOBindingService.h"
#include "ServiceContext.h"
#include "smacros.h"
#include "stools.h"


int DeviceIOBindingService::GetServiceCapabilities(
    _tmd__GetServiceCapabilities         *tmd__GetServiceCapabilities,
    _tmd__GetServiceCapabilitiesResponse &tmd__GetServiceCapabilitiesResponse)
{
    UNUSED(tmd__GetServiceCapabilities);

    auto ctx = (ServiceContext*)soap->user;
    tmd__GetServiceCapabilitiesResponse.Capabilities = ctx->getDeviceIOServiceCapabilities(soap);

    return SOAP_OK;
}


int DeviceIOBindingService::GetDigitalInputs(
    _tmd__GetDigitalInputs         *tmd__GetDigitalInputs,
    _tmd__GetDigitalInputsResponse &tmd__GetDigitalInputsResponse)
{
    UNUSED(tmd__GetDigitalInputs);

    auto ctx = (ServiceContext*)soap->user;

    for(const auto& input : ctx->get_digital_inputs())
    {
        auto entry = soap_new_tt__DigitalInput(soap);
        if(!entry)
            continue;

        entry->token     = input.token;
        entry->name      = input.name.c_str();
        entry->IdleState = soap_new_ptr(soap, input.idle_state);

        tmd__GetDigitalInputsResponse.DigitalInputs.push_back(entry);
    }

    return SOAP_OK;
}


int DeviceIOBindingService::GetDigitalOutputs(
    _tmd__GetDigitalOutputs         *tmd__GetDigitalOutputs,
    _tmd__GetDigitalOutputsResponse &tmd__GetDigitalOutputsResponse)
{
    UNUSED(tmd__GetDigitalOutputs);

    auto ctx = (ServiceContext*)soap->user;

    for(const auto& output : ctx->get_relay_outputs())
    {
        auto entry = soap_new_tt__RelayOutput(soap);
        if(!entry)
            continue;

        entry->token = output.token;
        entry->name  = output.name.c_str();

        entry->Properties = soap_new_tt__RelayOutputSettings(soap);
        if(entry->Properties)
        {
            entry->Properties->Mode      = output.mode;
            entry->Properties->DelayTime = 0;
            entry->Properties->IdleState = output.idle_state;
        }

        tmd__GetDigitalOutputsResponse.DigitalOutputs.push_back(entry);
    }

    return SOAP_OK;
}


int DeviceIOBindingService::SetRelayOutputState(
    _tmd__SetRelayOutputState         *tmd__SetRelayOutputState,
    _tmd__SetRelayOutputStateResponse &tmd__SetRelayOutputStateResponse)
{
    UNUSED(tmd__SetRelayOutputStateResponse);

    auto ctx = (ServiceContext*)soap->user;
    if(!ctx->set_relay_state(tmd__SetRelayOutputState->RelayOutputToken, tmd__SetRelayOutputState->LogicalState))
        return soap_sender_fault(soap, "Unknown relay output token", nullptr);

    return SOAP_OK;
}
