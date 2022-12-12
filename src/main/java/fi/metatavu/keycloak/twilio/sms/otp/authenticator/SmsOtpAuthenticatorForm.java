package fi.metatavu.keycloak.twilio.sms.otp.authenticator;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import lombok.extern.jbosslog.JBossLog;
import org.eclipse.microprofile.config.ConfigProvider;
import org.keycloak.authentication.*;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;

@JBossLog
public class SmsOtpAuthenticatorForm implements Authenticator {

    static final String ID = "twilio-sms-otp-form";
    public static final String OTP_CODE = "otpCode";
    public static final String RESEND_CODE_FIELD_NAME = "resendCode";
    public static final String CANCEL_FIELD_NAME = "cancel";
    private static final Integer SMS_CODE_LENGTH = ConfigProvider.getConfig().getValue("kc.otp.length", Integer.class);
    private static final String TWILIO_ACCOUNT_SID = ConfigProvider.getConfig().getValue("kc.twilio.account.sid", String.class);
    private static final String TWILIO_AUTH_TOKEN = ConfigProvider.getConfig().getValue("kc.twilio.auth.token", String.class);
    private static final String TWILIO_PHONE_NUMBER = ConfigProvider.getConfig().getValue("kc.twilio.phone.number", String.class);


    public SmsOtpAuthenticatorForm() {
    }

    /**
     * This method is being run by Keycloak upon executing.
     *
     * @param context context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        challenge(context, null);

    }

    /**
     * Validates form data and appends possible error message to form
     *
     * @param context context
     * @param errorMessage error message
     */
    private void challenge(AuthenticationFlowContext context, FormMessage errorMessage) {
        generateAndSendSmsCode(context);
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        if (errorMessage != null) {
            form.setErrors(List.of(errorMessage));
        }

        Response response = form.createForm("sms-code-form.ftl");
        context.challenge(response);
    }

    /**
     * Generates SMS OTP code and sends it.
     *
     * @param context Authentication flow context
     */
    private void generateAndSendSmsCode(AuthenticationFlowContext context) {
        if (context.getAuthenticationSession().getAuthNote(OTP_CODE) != null) {
            return;
        }

        String smsCode = SecretGenerator.getInstance().randomString(SMS_CODE_LENGTH, SecretGenerator.DIGITS);
        sendSmsWithCode(context.getRealm(), context.getUser(), smsCode);
        context.getAuthenticationSession().setAuthNote(OTP_CODE, smsCode);
    }

    /**
     * Called when form is being submitted.
     * Checks what form button is pressed and acts accordingly.
     * If correct OTP code is given, this Authentication Flow Context is marked successful.
     *
     * @param context context
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey(RESEND_CODE_FIELD_NAME)) {
            resetOtpCode(context);
            challenge(context, null);
            return;
        }

        if (formData.containsKey(CANCEL_FIELD_NAME)) {
            resetOtpCode(context);
            context.resetFlow();
            return;
        }

        if (formData.getFirst(OTP_CODE) != null) {
            int givenSmsCode = Integer.parseInt(formData.getFirst(OTP_CODE));
            boolean valid = validateCode(context, givenSmsCode);

            if (!valid) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                challenge(context, new FormMessage(Messages.INVALID_ACCESS_CODE));
                return;
            }

            resetOtpCode(context);
            context.success();
        }
    }

    /**
     * Resets current valid SMS OTP code.
     *
     * @param context context
     */
    private void resetOtpCode(AuthenticationFlowContext context) {
        context.getAuthenticationSession().removeAuthNote(OTP_CODE);
    }

    /**
     * Validates that given SMS OTP code is correct.
     *
     * @param context context
     * @param givenCode given code
     * @return Whether given code is correct
     */
    private boolean validateCode(AuthenticationFlowContext context, int givenCode) {
        int smsCode = Integer.parseInt(context.getAuthenticationSession().getAuthNote(OTP_CODE));
        return givenCode == smsCode;
    }

    /**
     * Sends SMS with OTP code to user.
     * Throws error if phone number is not found on user.
     *
     * @param realm realm
     * @param user user
     * @param smsCode sms code
     */
    private void sendSmsWithCode(RealmModel realm, UserModel user, String smsCode) {
        String userPhoneNumber = user.getFirstAttribute(PhoneNumberForm.PHONE_NUMBER_ATTRIBUTE_NAME);

        if (userPhoneNumber == null) {
            log.warnf("Could not send OTP Code SMS due to missing phone number. Realm=%s User=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Twilio.init(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
        Message.creator(
                new PhoneNumber(userPhoneNumber),
                new PhoneNumber(TWILIO_PHONE_NUMBER),
                String.format("Your one time code for Votech is: %s", smsCode)
        ).create();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
}
