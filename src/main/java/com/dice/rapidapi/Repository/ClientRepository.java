package com.dice.rapidapi.Repository;

import com.dice.rapidapi.Model.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, Long> {

    public Client findByEmail(String email);
}
