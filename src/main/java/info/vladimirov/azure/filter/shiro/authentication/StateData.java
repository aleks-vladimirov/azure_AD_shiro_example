// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package info.vladimirov.azure.filter.shiro.authentication;

import lombok.Getter;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Objects;

@Getter
public class StateData implements Serializable {
    private final String nonce;

    private final LocalDateTime creationDate;

    private final String state;

    public StateData(String nonce, LocalDateTime creationDate, String state) {
        this.nonce = nonce;
        this.creationDate = creationDate;
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }


    @Override
    public String toString() {
        return "StateData{" +
                "nonce='" + nonce + '\'' +
                ", expirationDate=" + creationDate +
                ", state='" + state + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof StateData)) return false;
        StateData stateData = (StateData) o;
        return Objects.equals(getNonce(), stateData.getNonce()) && Objects.equals(getCreationDate(), stateData.getCreationDate()) && Objects.equals(getState(), stateData.getState());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getNonce(), getCreationDate(), getState());
    }
}