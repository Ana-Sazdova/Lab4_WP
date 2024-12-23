package mk.ukim.finki.wp.lab.BootStrap;

import jakarta.annotation.PostConstruct;
import mk.ukim.finki.wp.lab.model.Album;
import mk.ukim.finki.wp.lab.model.Artist;
import mk.ukim.finki.wp.lab.model.Song;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class DataHolder {
    public static List<Artist> ARTISTS=new ArrayList<>();
    public static List<Song> SONGS =new ArrayList<>();
    public static List<Album> ALBUMS =new ArrayList<>();
    @PostConstruct
     public void init()

    {
        ARTISTS.add(new Artist(1L, "Bob", "Dylan", "An iconic American singer-songwriter and Nobel laureate known for his influential folk and rock music."));
        ARTISTS.add(new Artist(2L, "Taylor", "Swift", "An American singer-songwriter known for her narrative songwriting and genre versatility."));
        ARTISTS.add(new Artist(3L, "Freddie", "Mercury", "The legendary frontman of Queen, celebrated for his powerful vocals and dynamic stage presence."));
        ARTISTS.add ( new Artist(4L, "Adele", "Adkins", "A British singer-songwriter famous for her soulful voice and deeply personal ballads."));
        ARTISTS.add(new Artist(5L, "Paul", "McCartney", "An English singer-songwriter and former Beatle, one of the most successful composers and performers in music history."));



        Album album1 = new Album("The Times They Are A-Changin'", "Folk", "1964");
        Album album2 = new Album("1989", "Pop", "2014");
        Album album3 = new Album("A Night at the Opera", "Rock", "1975");
        Album album4 = new Album("25", "Soul", "2015");
        Album album5 = new Album("Abbey Road", "Rock", "1969");

        ALBUMS.add(album1);
        ALBUMS.add(album2);
        ALBUMS.add(album3);
        ALBUMS.add(album4);
        ALBUMS.add(album5);

        SONGS.add(new Song("Blowin' in the Wind", "Folk", "pop",1997));
        SONGS.add(new Song("Shake It Off", "Pop", "Pop", 2014));
        SONGS.add(new Song( "Bohemian Rhapsody", "Rock", "pop", 2000));
        SONGS.add(new Song("Hello", "Soul", "soul", 2078));
        SONGS.add(new Song("Let It Be", "Rock", "Rock", 1999));

    }


}
