package br.com.rememo.persistence.flashcard;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface FlashcardRepository extends JpaRepository<FlashcardEntity, Long>, JpaSpecificationExecutor<FlashcardEntity> {

}
