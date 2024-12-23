package mk.ukim.finki.wp.lab.repository;

import mk.ukim.finki.wp.lab.BootStrap.DataHolder;
import mk.ukim.finki.wp.lab.model.Artist;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Repository
public class ArtistRepository {


    public List<Artist> findAll() {

        return DataHolder.ARTISTS;
    }

    public Optional<Artist> findById(Long id) {
        return DataHolder.ARTISTS.stream().filter(artist -> artist.getId()==id).findFirst();

    }
}
