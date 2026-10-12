package br.com.rememo.persistence.deck;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DeckRepository extends JpaRepository<DeckEntity, Long> {
}
