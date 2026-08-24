package io.phasetwo.service.auth.idp.discovery.extemail;

import com.google.common.base.Strings;
import io.phasetwo.service.auth.idp.PublicAPI;
import io.phasetwo.service.auth.idp.Users;
import io.phasetwo.service.auth.idp.discovery.spi.HomeIdpDiscoverer;
import io.phasetwo.service.model.OrganizationModel;
import io.phasetwo.service.model.OrganizationProvider;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.*;
import java.util.stream.Collectors;

import static io.phasetwo.service.Orgs.ORG_CONFIG_VALIDATE_IDP_KEY;
import static io.phasetwo.service.Orgs.ORG_DOMAIN_CONFIG_KEY;
import static io.phasetwo.service.Orgs.ORG_VALIDATION_PENDING_CONFIG_KEY;

@PublicAPI(unstable = true)
public final class EmailHomeIdpDiscoverer implements HomeIdpDiscoverer {

    private static final Logger LOG = Logger.getLogger(EmailHomeIdpDiscoverer.class);
    private static final String EMAIL_ATTRIBUTE = "email";
    private final Users users;
    private final IdentityProviders identityProviders;
    private static final String ACCOUNT_HINT_QUERY_PARAM =
            AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX +
            "account_hint";

    @PublicAPI(unstable = true)
    public EmailHomeIdpDiscoverer(Users users, IdentityProviders identityProviders) {
        this.users = users;
        this.identityProviders = identityProviders;
    }

    @Override
    public List<IdentityProviderModel> discoverForUser(AuthenticationFlowContext context, String username) {

        String realmName = context.getRealm().getName();
        EmailHomeIdpDiscovererConfig config = new EmailHomeIdpDiscovererConfig(context.getAuthenticatorConfig());
        LOG.tracef("Trying to discover home IdP for username '%s' in realm '%s' with authenticator config '%s'",
                username, realmName, config == null ? "<unconfigured>" : config.getAlias());

        DomainExtractor domainExtractor = new DomainExtractor(config);
        LOG.tracef("Trying to discover home IdP for username '%s' in realm '%s' with authenticator config '%s'",
                username, realmName, config.getAlias());

        List<IdentityProviderModel> homeIdps = new ArrayList<>();

        final Optional<Domain> emailDomain;
        UserModel user = users.lookupBy(username);
        if (user == null) {
            LOG.tracef("No user found in AuthenticationFlowContext. Extracting domain from provided username '%s'.",
                    username);
            emailDomain = domainExtractor.extractFrom(username);
        } else {
            LOG.tracef("User found in AuthenticationFlowContext. Extracting domain from stored user '%s'.",
                    user.getId());
            if (EMAIL_ATTRIBUTE.equalsIgnoreCase(config.userAttribute())
                    && !user.isEmailVerified()
                    && config.requireVerifiedEmail()) {
                LOG.warnf("Email address of user '%s' is not verified and forwarding not enabled", user.getId());
                emailDomain = Optional.empty();
            } else {
                emailDomain = domainExtractor.extractFrom(user);
            }
        }

        if (emailDomain.isPresent()) {
            Domain domain = emailDomain.get();
            homeIdps = discoverHomeIdps(context, domain, user, username);
            if (homeIdps.isEmpty()) {
                LOG.debugf("Could not find home IdP for domain '%s' and user '%s' in realm '%s'",
                        domain, username, realmName);
            } else {
                String homeIdpsString = homeIdps.stream()
                        .map(IdentityProviderModel::getAlias)
                        .collect(Collectors.joining(","));
                LOG.infof("Found IdPs [%s] with domain '%s' for user '%s'", homeIdpsString, domain, username);
            }
        } else {
            LOG.warnf("Could not extract domain from email address '%s'", username);
        }

        return homeIdps;
    }

    // Note(fastly):
    //
    // Fastly implementation of discoverHomeIdps
    // See above function for original implementation.
    //
    private List<IdentityProviderModel> discoverHomeIdps(AuthenticationFlowContext context, Domain domain, UserModel user, String username) {
        final Map<String, String> linkedIdps;

        EmailHomeIdpDiscovererConfig config = new EmailHomeIdpDiscovererConfig(context.getAuthenticatorConfig());
        if (user == null || !config.forwardToLinkedIdp()) {
            LOG.tracef(
                "User '%s' is not stored locally or forwarding to linked IdP is disabled. Skipping discovery of linked IdPs.",
                username);
            return Collections.emptyList();
        }

        LOG.tracef(
            "Found local user '%s' and forwarding to linked IdP is enabled. Discovering linked IdPs.",
            username);

        linkedIdps = context.getSession().users()
                .getFederatedIdentitiesStream(context.getRealm(), user)
                .collect(
                    Collectors.toMap(FederatedIdentityModel::getIdentityProvider, FederatedIdentityModel::getUserName));

        // Custom Fastly lookup mechanism.
        //
        // 1. Get all Orgs linked to the user
        // 3. Filter orgs based on inbound client (i.e. only return SigSci orgs for sigsci-only customers etc)
        // 4. Filter orgs to only those with force_sso
        // 2. Filter to only enabled IdPs
        AuthenticationSessionModel authSession =
            context.getAuthenticationSession();
        String clientID = authSession.getClient().getClientId();
        OrganizationProvider orgs = context.getSession().getProvider(OrganizationProvider.class);
        String userDefaultCID = Objects.toString(
                user.getFirstAttribute("default_cid"),
            "");

        List<IdentityProviderModel> enabledIdpsForUserOrgs =
            orgs.getUserOrganizationsStream(
                    context.getRealm(), user)
                .filter(o -> {
                    boolean isFastlyCustomer = isFastlyCustomer(o);

                    if(clientID.equals("sigsci-dashboard")) {
                        return isCorp(o);
                    }

                    if(!isFastlyCustomer && !clientID.equals("manage-fastly-com")) {
                        return isCorp(o);
                    }

                    return isFastlyCustomer && hasForceSso(o);
                })
                .sorted((o1, o2) -> {
                    if(clientID.equals("sigsci-dashboard")) {
                        String corp_id = o1.getFirstAttribute("corp_id");
                        if(corp_id != null && !corp_id.isEmpty()) {
                            return -1;
                        }
                    }
                    else {
                        String customer_id = o1.getFirstAttribute("customer_id");
                        if(customer_id != null && !customer_id.isEmpty()) {
                            return -1;
                        }

                        String organizationID = o1.getFirstAttribute("organization_id");
                        if(organizationID != null && !organizationID.isEmpty()) {
                            return -1;
                        }
                    }
                    return 1;
                })
                .sorted((o1, o2) -> {
                    if(o1.getFirstAttribute("customer_id") != null && o1.getFirstAttribute("customer_id").equals(userDefaultCID)) return -1;
                    else return 1;
                })
                .sorted((o1, o2) -> {
                    String accountHint = authSession.getClientNote(
                        ACCOUNT_HINT_QUERY_PARAM
                    );
                    String customerID = o1.getFirstAttribute("customer_id");
                    if (accountHint != null && !accountHint.isEmpty() &&
                        customerID != null && !customerID.isEmpty() &&
                        accountHint == customerID) {
                        return -1;
                    }

                    String organizationID = o1.getFirstAttribute("organization_id");
                    if (accountHint != null && !accountHint.isEmpty() &&
                        organizationID != null && !organizationID.isEmpty() &&
                        accountHint == organizationID) {
                        return -1;
                    }
                    return 1;
                })
                .flatMap(o -> o.getIdentityProvidersStream())
                .filter(IdentityProviderModel::isEnabled)
                .collect(Collectors.toList());

        List<IdentityProviderModel> homeIdps = getLinkedIdpsFrom(enabledIdpsForUserOrgs, linkedIdps);

        logFoundIdps("linked", "matching", homeIdps, domain, username);

        return homeIdps;
    }

    private void logFoundIdps(String idpQualifier, String domainQualifier, List<IdentityProviderModel> homeIdps, Domain domain, String username) {
        String homeIdpsString = homeIdps.stream()
                .map(IdentityProviderModel::getAlias)
                .collect(Collectors.joining(","));
        LOG.tracef("Found %s IdPs [%s] with %s domain '%s' for user '%s'",
                idpQualifier, homeIdpsString, domainQualifier, domain, username);
    }

    /**
     * Given a list of idps and a map of idp alias to federated username, return a subset of the list that are contained in the map keys.
     * @param enabledIdpsWithMatchingDomain A list of identity providers
     * @param linkedIdps A map of idp alias to federated username
     * @returns A subset of the list that are contained in the map keys
     */
    private List<IdentityProviderModel> getLinkedIdpsFrom(List<IdentityProviderModel> enabledIdpsWithMatchingDomain, Map<String, String> linkedIdps) {
        return enabledIdpsWithMatchingDomain.stream()
                .filter(it -> linkedIdps.containsKey(it.getAlias()))
                .collect(Collectors.toList());
    }

    private boolean isIdpValidationPending(IdentityProviderModel idp) {
        return Boolean.parseBoolean(
                Optional.ofNullable(idp.getConfig())
                        .map(cfg -> cfg.get(ORG_VALIDATION_PENDING_CONFIG_KEY))
                        .orElse(null));
    }

//
//    private List<IdentityProviderModel> filterIdpsWithMatchingDomainFrom(List<IdentityProviderModel> enabledIdps, Domain domain, HomeIdpDiscoveryConfig config) {
//        String userAttributeName = config.userAttribute();
//        List<IdentityProviderModel> idpsWithMatchingDomain = enabledIdps.stream()
//                .filter(it -> new io.phasetwo.service.auth.idp.IdentityProviderModelConfig(it).supportsDomain(userAttributeName, domain))
//                .collect(Collectors.toList());
//        LOG.tracef("IdPs with matching domain '%s' for attribute '%s': %s", domain, userAttributeName,
//                idpsWithMatchingDomain.stream().map(IdentityProviderModel::getAlias).collect(Collectors.joining(",")));
//        return idpsWithMatchingDomain;
//    }

    /**
     * @returns A list of all enabled idps for a realm.
     */
    private List<IdentityProviderModel> determineEnabledIdps(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        List<IdentityProviderModel> enabledIdps = context.getSession().identityProviders().getAllStream()
                .filter(IdentityProviderModel::isEnabled)
                .collect(Collectors.toList());
        LOG.tracef("Enabled IdPs in realm '%s': %s",
                realm.getName(),
                enabledIdps.stream().map(IdentityProviderModel::getAlias).collect(Collectors.joining(",")));
        return enabledIdps;
    }

    @Override
    public void close() {
    }

    private boolean isCorp(OrganizationModel org) {
        String corp = org.getFirstAttribute("corp_id");
        boolean hasCorpID = corp != null && !corp.isEmpty();

        return hasCorpID;
    }

    private boolean isFastlyCustomer(OrganizationModel org) {
        String customerID = org.getFirstAttribute("customer_id");
        boolean hasCustomerID = customerID != null && !customerID.isEmpty();

        String organizationID = org.getFirstAttribute("organization_id");
        boolean hasOrganizationID = organizationID != null && !organizationID.isEmpty();

        return hasCustomerID || hasOrganizationID;
    }

    private boolean hasForceSso(OrganizationModel org) {
        String forceSSO = org.getFirstAttribute("force_sso");
        boolean hasForceSSO = forceSSO != null && forceSSO.equals("1");

        return hasForceSSO;
    }
}
