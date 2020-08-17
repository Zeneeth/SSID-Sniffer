# Code from Annas Uni work

import java.util.List;

import org.springframework.ui.Model;

import com.mapbox.api.geocoding.v5.MapboxGeocoding;
import com.mapbox.api.geocoding.v5.models.CarmenFeature;
import com.mapbox.api.geocoding.v5.models.GeocodingResponse;
import com.mapbox.geojson.Point;

import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import uk.ac.man.cs.eventlite.entities.Venue;

public class MapBoxApi {
	private final static String MAPBOX_ACCESS_TOKEN = "pk.eyJ1IjoiZzAyIiwiYSI6ImNrOGoweDZncjA0bHczcW10NHFrejM0NzgifQ.1kccWEN-CE2PIRjGw6amEA";

	public static void getAndSetCoordinates(Venue venue, Model model)
	{
		//Build the MapBox request
	       MapboxGeocoding mapboxGeocoding = MapboxGeocoding.builder()
	    		   .accessToken(MAPBOX_ACCESS_TOKEN)
	    		   .query(venue.getRoadName() + ", " + venue.getPostcode())
	    		   .build();

	       //Make a call to the server and get the response containing the latitude and longitude
	       mapboxGeocoding.enqueueCall(new Callback<GeocodingResponse>() {
	    		@Override
	    		public void onResponse(Call<GeocodingResponse> call, Response<GeocodingResponse> response) {

	    			List<CarmenFeature> results = response.body().features();

	    			if (results.size() > 0)
	    			{
	    			  // Get the first Point
	    			  Point firstResultPoint = results.get(0).center();

	    			  venue.setLatitude(firstResultPoint.latitude());
	    			  venue.setLongitude(firstResultPoint.longitude());
	    			}

	    			else
	    			{
	    				//If any error appears, add it to the model to alert the user
	    				model.addAttribute("mapboxError", "There was a problem finding your location");
	    			}
	    		}

	    		@Override
	    		public void onFailure(Call<GeocodingResponse> call, Throwable throwable) {
	    			throwable.printStackTrace();
	    		}
	    	});

	}
}
