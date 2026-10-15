package br.com.rememo.persistence.deck;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface DeckRepository extends JpaRepository<DeckEntity, Long>, JpaSpecificationExecutor<DeckEntity> {

}
