package info.vladimirov.azure.filter.shiro.authentication;



import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class SessionManagementHelper {

    public static final String STATES = "states";
    private static final Integer STATE_TTL = 3600;

    public static final String ORIGIN_URL = "ORIGIN_URL";


    public static StateData removeStateFromSession(HttpSession session, String state) {
        Map<String, StateData> states = (Map<String, StateData>) session.getAttribute(STATES);
        if (states != null && states.containsKey(state)) {
            eliminateExpiredStates(states);
            StateData stateData = states.get(state);
            if (stateData != null) {
                states.remove(state);
                return stateData;
            }
        }
        return null;
    }

    private static void eliminateExpiredStates(Map<String, StateData> map) {
        Iterator<Map.Entry<String, StateData>> it = map.entrySet().iterator();

        LocalDateTime currTime =  LocalDateTime.now();
        while (it.hasNext()) {
            Map.Entry<String, StateData> entry = it.next();
            long diffInSeconds = ChronoUnit.MILLIS.
                    between(currTime, entry.getValue().getCreationDate());

            if (diffInSeconds > STATE_TTL) {
                it.remove();
            }
        }
    }

    public static void storeStateAndNonceInSession(HttpSession session, String state, String nonce) {

        // state parameter to validate response from Authorization server and nonce parameter to validate idToken
        Map<String, StateData> stateAttribute;
        if (session.getAttribute(STATES) == null) {
            stateAttribute = new HashMap<>();
        } else {
            stateAttribute = (Map<String, StateData>) session.getAttribute(STATES);
        }
        stateAttribute.put(state, new StateData(nonce, LocalDateTime.now(), state));
        session.setAttribute(STATES, stateAttribute);
    }

    public static void storeURLPath(HttpSession servletRequest, String url) {
        servletRequest.setAttribute(ORIGIN_URL, url);
    }

}
