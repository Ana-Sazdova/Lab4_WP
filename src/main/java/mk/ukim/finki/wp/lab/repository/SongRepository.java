package mk.ukim.finki.wp.lab.repository;

import mk.ukim.finki.wp.lab.BootStrap.DataHolder;
import mk.ukim.finki.wp.lab.model.Artist;
import mk.ukim.finki.wp.lab.model.Song;
import org.springframework.boot.autoconfigure.jackson.JacksonProperties;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static mk.ukim.finki.wp.lab.BootStrap.DataHolder.SONGS;

@Repository
public interface SongRepository extends JpaRepository<Song, Long> {
    List<Song> findAllByAlbum_Id(Long albumId);
   Optional<Song> findByTrackId(String trackId);

}
