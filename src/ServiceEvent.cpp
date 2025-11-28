#include "soapEventBindingService.h"
#include "soapNotificationProducerBindingService.h"
#include "soapPullPointSubscriptionBindingService.h"
#include "soapSubscriptionManagerBindingService.h"

#include "ServiceContext.h"
#include "smacros.h"

#include <ctime>

namespace
{
    std::chrono::system_clock::time_point default_termination()
    {
        return std::chrono::system_clock::now() + std::chrono::minutes(5);
    }
}

int EventBindingService::GetEventProperties(
    _tev__GetEventProperties         *tev__GetEventProperties,
    _tev__GetEventPropertiesResponse &tev__GetEventPropertiesResponse)
{
    UNUSED(tev__GetEventProperties);
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;

    tev__GetEventPropertiesResponse.FixedTopicSet = soap_new_bool(soap, true);
    tev__GetEventPropertiesResponse.TopicSet      = soap_new_wstop__TopicSetType(soap);

    tev__GetEventPropertiesResponse.TopicExpressionDialect.push_back("http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet");
    tev__GetEventPropertiesResponse.MessageContentFilterDialect.push_back("http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter");

    auto topics = ctx->get_event_topics();
    for(const auto &topic : topics)
        tev__GetEventPropertiesResponse.TopicNamespaceLocation.push_back(topic);

    return SOAP_OK;
}


int NotificationProducerBindingService::CreatePullPointSubscription(
    _tev__CreatePullPointSubscription         *tev__CreatePullPointSubscription,
    _tev__CreatePullPointSubscriptionResponse &tev__CreatePullPointSubscriptionResponse)
{
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;

    auto termination = default_termination();
    if(tev__CreatePullPointSubscription && tev__CreatePullPointSubscription->InitialTerminationTime)
        termination = std::chrono::system_clock::now() + std::chrono::seconds(30);

    auto ref = ctx->create_pull_point(termination);

    tev__CreatePullPointSubscriptionResponse.SubscriptionReference = soap_new_wsa5__EndpointReferenceType(soap);
    if(tev__CreatePullPointSubscriptionResponse.SubscriptionReference)
    {
        tev__CreatePullPointSubscriptionResponse.SubscriptionReference->Address = soap_new_std_string(soap, ctx->getXAddr(soap) + "/events/" + ref);
    }

    tev__CreatePullPointSubscriptionResponse.CurrentTime    = time(nullptr);
    tev__CreatePullPointSubscriptionResponse.TerminationTime = std::chrono::system_clock::to_time_t(termination);

    return SOAP_OK;
}


int PullPointSubscriptionBindingService::PullMessages(
    _tev__PullMessages         *tev__PullMessages,
    _tev__PullMessagesResponse &tev__PullMessagesResponse)
{
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;
    std::vector<ServiceContext::EventMessage> messages;
    std::chrono::system_clock::time_point termination;

    auto reference = soap->endpoint ? std::string(soap->endpoint) : std::string();
    size_t limit = tev__PullMessages ? tev__PullMessages->MessageLimit : 0;
    if(limit == 0)
        limit = 10;

    if(!ctx->pop_messages(reference, limit, messages, termination))
        return soap_sender_fault(soap, "Unknown PullPoint", nullptr);

    tev__PullMessagesResponse.CurrentTime     = time(nullptr);
    tev__PullMessagesResponse.TerminationTime = std::chrono::system_clock::to_time_t(termination);

    for(const auto &msg : messages)
    {
        auto holder = soap_new_wsnt__NotificationMessageHolderType(soap);
        if(!holder)
            continue;

        holder->Topic = soap_new_wsnt__TopicExpressionType(soap);
        if(holder->Topic)
        {
            holder->Topic->Dialect = "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet";
            holder->Topic->__mixed = msg.topic;
        }

        holder->Message = soap_new_wsnt__NotificationMessageHolderType::Message(soap);
        if(holder->Message)
        {
            auto payload = soap_new_tt__Message(soap);
            if(payload)
            {
                payload->UtcTime = std::chrono::system_clock::to_time_t(msg.timestamp);
                payload->PropertyOperation = soap_new_tt__PropertyOperation(soap, tt__PropertyOperation::Changed);

                auto data = soap_new_tt__ItemList(soap);
                if(data)
                {
                    auto simple = soap_new_tt__SimpleItem(soap);
                    if(simple)
                    {
                        simple->Name  = "State";
                        simple->Value = msg.active ? "true" : "false";
                        data->SimpleItem.push_back(simple);
                    }

                    auto last_change = soap_new_tt__SimpleItem(soap);
                    auto ctx = (ServiceContext*)soap->user;
                    if(last_change && ctx)
                    {
                        last_change->Name  = "LastChange";
                        last_change->Value = ctx->format_timestamp(msg.timestamp);
                        data->SimpleItem.push_back(last_change);
                    }
                }
                payload->Data = data;
            }
            holder->Message->__any = payload;
        }

        tev__PullMessagesResponse.wsnt__NotificationMessage.push_back(holder);
    }

    return SOAP_OK;
}


int PullPointSubscriptionBindingService::Renew(
    _tev__Renew         *tev__Renew,
    _tev__RenewResponse &tev__RenewResponse)
{
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;
    auto reference = soap->endpoint ? std::string(soap->endpoint) : std::string();
    auto termination = default_termination();

    if(tev__Renew && tev__Renew->TerminationTime)
        termination = std::chrono::system_clock::now() + std::chrono::seconds(30);

    if(!ctx->renew_pull_point(reference, termination))
        return soap_sender_fault(soap, "Unknown PullPoint", nullptr);

    tev__RenewResponse.TerminationTime = std::chrono::system_clock::to_time_t(termination);
    return SOAP_OK;
}


int PullPointSubscriptionBindingService::Unsubscribe(
    _tev__Unsubscribe         *tev__Unsubscribe,
    _tev__UnsubscribeResponse &tev__UnsubscribeResponse)
{
    UNUSED(tev__Unsubscribe);
    UNUSED(tev__UnsubscribeResponse);
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;
    auto reference = soap->endpoint ? std::string(soap->endpoint) : std::string();

    if(!ctx->remove_pull_point(reference))
        return soap_sender_fault(soap, "Unknown PullPoint", nullptr);

    return SOAP_OK;
}


int SubscriptionManagerBindingService::Renew(
    _tev__Renew         *tev__Renew,
    _tev__RenewResponse &tev__RenewResponse)
{
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;
    auto reference = soap->endpoint ? std::string(soap->endpoint) : std::string();
    auto termination = default_termination();

    if(tev__Renew && tev__Renew->TerminationTime)
        termination = std::chrono::system_clock::now() + std::chrono::seconds(30);

    if(!ctx->renew_pull_point(reference, termination))
        return soap_sender_fault(soap, "Unknown PullPoint", nullptr);

    tev__RenewResponse.TerminationTime = std::chrono::system_clock::to_time_t(termination);
    return SOAP_OK;
}


int SubscriptionManagerBindingService::Unsubscribe(
    _tev__Unsubscribe         *tev__Unsubscribe,
    _tev__UnsubscribeResponse &tev__UnsubscribeResponse)
{
    UNUSED(tev__Unsubscribe);
    UNUSED(tev__UnsubscribeResponse);
    DEBUG_MSG("Event: %s\n", __FUNCTION__);

    auto ctx = (ServiceContext*)soap->user;
    auto reference = soap->endpoint ? std::string(soap->endpoint) : std::string();

    if(!ctx->remove_pull_point(reference))
        return soap_sender_fault(soap, "Unknown PullPoint", nullptr);

    return SOAP_OK;
}

