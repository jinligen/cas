package org.apereo.cas.ws.idp.web;

import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.authentication.AuthenticationServiceSelectionStrategy;
import org.apereo.cas.authentication.SecurityTokenServiceTokenFetcher;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.ticket.SecurityTokenTicketFactory;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.http.HttpClient;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.support.CookieRetrievingCookieGenerator;
import org.apereo.cas.web.support.CookieUtils;
import org.apereo.cas.ws.idp.WSFederationConstants;
import org.apereo.cas.ws.idp.services.WSFederationRelyingPartyTokenProducer;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/**
 * This is {@link WSFederationValidateRequestCallbackController}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@Slf4j
public class WSFederationValidateRequestCallbackController extends BaseWSFederationRequestController {

    private final WSFederationRelyingPartyTokenProducer relyingPartyTokenProducer;
    private final TicketValidator ticketValidator;
    private final SecurityTokenServiceTokenFetcher securityTokenServiceTokenFetcher;

    public WSFederationValidateRequestCallbackController(final ServicesManager servicesManager,
                                                         final ServiceFactory<WebApplicationService> webApplicationServiceFactory,
                                                         final CasConfigurationProperties casProperties,
                                                         final WSFederationRelyingPartyTokenProducer relyingPartyTokenProducer,
                                                         final AuthenticationServiceSelectionStrategy serviceSelectionStrategy,
                                                         final HttpClient httpClient,
                                                         final SecurityTokenTicketFactory securityTokenTicketFactory,
                                                         final TicketRegistry ticketRegistry,
                                                         final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator,
                                                         final TicketRegistrySupport ticketRegistrySupport,
                                                         final TicketValidator ticketValidator,
                                                         final Service callbackService,
                                                         final SecurityTokenServiceTokenFetcher securityTokenServiceTokenFetcher) {
        super(servicesManager,
            webApplicationServiceFactory, casProperties,
            serviceSelectionStrategy, httpClient, securityTokenTicketFactory,
            ticketRegistry, ticketGrantingTicketCookieGenerator,
            ticketRegistrySupport, callbackService);
        this.relyingPartyTokenProducer = relyingPartyTokenProducer;
        this.ticketValidator = ticketValidator;
        this.securityTokenServiceTokenFetcher = securityTokenServiceTokenFetcher;
    }

    private static ModelAndView postResponseBackToRelyingParty(final String rpToken,
                                                               final WSFederationRequest fedRequest) {
        val postUrl = StringUtils.isNotBlank(fedRequest.getWreply()) ? fedRequest.getWreply() : fedRequest.getWtrealm();

        val parameters = new HashMap<String, Object>();
        parameters.put(WSFederationConstants.WA, WSFederationConstants.WSIGNIN10);
        parameters.put(WSFederationConstants.WRESULT, StringEscapeUtils.unescapeHtml4(rpToken));
        parameters.put(WSFederationConstants.WTREALM, fedRequest.getWtrealm());

        if (StringUtils.isNotBlank(fedRequest.getWctx())) {
            parameters.put(WSFederationConstants.WCTX, fedRequest.getWctx());
        }

        LOGGER.trace("Posting relying party token to [{}]", postUrl);
        return new ModelAndView(CasWebflowConstants.VIEW_ID_POST_RESPONSE,
            CollectionUtils.wrap("originalUrl", postUrl, "parameters", parameters));
    }

    private SecurityToken fetchSecurityTokenFromAssertion(final Assertion assertion, final Service targetService) {
        val principal = assertion.getPrincipal().getName();
        val token = this.securityTokenServiceTokenFetcher.fetch(targetService, principal);
        if (!token.isPresent()) {
            LOGGER.warn("No security token could be retrieved for service [{}] and principal [{}]", targetService, principal);
            throw new UnauthorizedServiceException(UnauthorizedServiceException.CODE_UNAUTHZ_SERVICE);
        }
        return token.get();
    }

    /**
     * Handle federation request.
     *
     * @param response the response
     * @param request  the request
     * @return the model and view
     * @throws Exception the exception
     */
    @GetMapping(path = WSFederationConstants.ENDPOINT_FEDERATION_REQUEST_CALLBACK)
    protected ModelAndView handleFederationRequest(final HttpServletResponse response, final HttpServletRequest request) throws Exception {
        val fedRequest = WSFederationRequest.of(request);
        LOGGER.debug("Received callback profile request [{}]", request.getRequestURI());

        val serviceUrl = constructServiceUrl(request, response, fedRequest);
        val targetService = this.serviceSelectionStrategy.resolveServiceFrom(this.webApplicationServiceFactory.createService(serviceUrl));
        val service = findAndValidateFederationRequestForRegisteredService(targetService, fedRequest);
        LOGGER.debug("Located matching service [{}]", service);

        val ticket = CommonUtils.safeGetParameter(request, CasProtocolConstants.PARAMETER_TICKET);
        if (StringUtils.isBlank(ticket)) {
            LOGGER.error("Can not validate the request because no [{}] is provided via the request", CasProtocolConstants.PARAMETER_TICKET);
            return new ModelAndView(CasWebflowConstants.VIEW_ID_ERROR, new HashMap<>(), HttpStatus.FORBIDDEN);
        }

        val assertion = validateRequestAndBuildCasAssertion(response, request, fedRequest);
        val securityTokenReq = getSecurityTokenFromRequest(request);
        val securityToken = FunctionUtils.doIfNull(securityTokenReq,
            () -> {
                LOGGER.debug("No security token is yet available. Invoking security token service to issue token");
                return fetchSecurityTokenFromAssertion(assertion, targetService);
            },
            () -> securityTokenReq)
            .get();
        addSecurityTokenTicketToRegistry(request, securityToken);
        val rpToken = produceRelyingPartyToken(request, targetService, fedRequest, securityToken, assertion);
        return postResponseBackToRelyingParty(rpToken, fedRequest);
    }

    private void addSecurityTokenTicketToRegistry(final HttpServletRequest request, final SecurityToken securityToken) {
        LOGGER.trace("Creating security token as a ticket to CAS ticket registry...");
        val tgt = CookieUtils.getTicketGrantingTicketFromRequest(ticketGrantingTicketCookieGenerator, ticketRegistry, request);
        val ticket = securityTokenTicketFactory.create(tgt, securityToken);
        LOGGER.trace("Created security token ticket [{}]", ticket);
        this.ticketRegistry.addTicket(ticket);
        LOGGER.trace("Added security token as a ticket to CAS ticket registry...");
        this.ticketRegistry.updateTicket(tgt);
    }

    private String produceRelyingPartyToken(final HttpServletRequest request, final Service targetService,
                                            final WSFederationRequest fedRequest, final SecurityToken securityToken,
                                            final Assertion assertion) {
        val service = findAndValidateFederationRequestForRegisteredService(targetService, fedRequest);
        LOGGER.debug("Located registered service [{}] to create relying-party tokens...", service);
        return relyingPartyTokenProducer.produce(securityToken, service, fedRequest, request, assertion);
    }

    private Assertion validateRequestAndBuildCasAssertion(final HttpServletResponse response,
                                                          final HttpServletRequest request,
                                                          final WSFederationRequest fedRequest) throws Exception {
        val ticket = CommonUtils.safeGetParameter(request, CasProtocolConstants.PARAMETER_TICKET);
        val serviceUrl = constructServiceUrl(request, response, fedRequest);
        LOGGER.trace("Created service url for validation: [{}]", serviceUrl);
        val assertion = this.ticketValidator.validate(ticket, serviceUrl);
        LOGGER.debug("Located CAS assertion [{}]", assertion);
        return assertion;
    }

}
