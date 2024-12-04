$(function(){
	var networks = undefined;
	var global_timer = undefined;

	function showSettingsFields() {
		var field_to_show = $(this).find(':selected').attr('value');
		$('#ethernet').hide();
		$('#ethernet-dhcp').hide();
		$('#wlan').hide();

		$('#' + field_to_show).show();
	}

	$('#ethernet').hide();
	$('#ethernet-dhcpp').hide();
	$('#wlan').hide();

	$('#eth_ipaddress').ipaddress();
	$('#eth_subnet').ipaddress();
	$('#eth_gateway').ipaddress();
	$('#eth_dns').ipaddress();

	function showHideEnterpriseSettings() {
		var security = $(this).find(':selected').attr('data-security');
		if(security === 'enterprise') {
			$('#identity-group').show();
		} else {
			$('#identity-group').hide();
		}
	}

	$('#ssid-select').change(showHideEnterpriseSettings);
	$('#network-select').change(showSettingsFields);

	async function fetchNetworks() {

		console.log("fetchNetworks");
		try {
			// jQuery $.get in ein Promise umwandeln
			console.log("awaiting networks");
			const data = await new Promise((resolve, reject) => {
				$.get("/networks", resolve).fail(reject);
			});
	
			console.log("got networks");
			const config = JSON.parse(data);
	
			if (config.ssids.length > 0) {
				$('#network-select').append(
					$('<option>')
						.text("WLAN")
						.attr('value', "wlan")
				);
				$('#wlan').show();
			} else {
				$('#wlan').hide();
			}
	
			if (config.ethernet && config.ethernet !== "None") {
				$('#network-select').append(
					$('<option>')
						.text("Kabelgebundenes Netzwerk - DHCP")
						.attr('value', "ethernet-dhcp")
				);
	
				$('#network-select').append(
					$('<option>')
						.text("Kabelgebundenes Netzwerk - Manuell")
						.attr('value', "ethernet")
				);
	
				if (config.ethernet.Static && config.ethernet.Static.length > 0) {
					$('#eth_ipaddress').val(config.ethernet.Static[0]);
					$('#eth_subnet').val(config.ethernet.Static[1]);
					$('#eth_gateway').val(config.ethernet.Static[2]);
					$('#eth_dns').val(config.ethernet.Static[3]);
				}
	
				if (config.ethernet.Dhcp && config.ethernet.Dhcp.length > 0) {
					$('#eth_ipaddress').val(config.ethernet.Dhcp[0]);
					$('#eth_subnet').val(config.ethernet.Dhcp[1]);
					$('#eth_gateway').val(config.ethernet.Dhcp[2]);
					$('#eth_dns').val(config.ethernet.Dhcp[3]);
				}
			}
	
			jQuery.proxy(showSettingsFields, $('#network-select'))();
	
			if (config.ssids.length === 0) {
				$('.before-submit').hide();
				$('#no-networks-message').removeClass('hidden');
			} else {
				$.each(config.ssids, function (i, val) {
					$('#ssid-select').append(
						$('<option>')
							.text(val.ssid)
							.attr('value', val.ssid)
							.attr('data-security', val.security)
					);
				});
	
				jQuery.proxy(showHideEnterpriseSettings, $('#ssid-select'))();
			}
		} catch (error) {
			console.error("Fehler beim Abrufen der Netzwerke:", error);
		}
	}

	fetchNetworks();
	/*
	struct ConnectionResponseState {
		status: String,
		connected: bool,
		error:bool,
	}
	*/
	$('#retry-button').click(function(ev) {
		ev.preventDefault();
		$('.before-submit').show();
		$('#submit-message').addClass('hidden');
		$('#connection_status').text('Bitte warten...');
		$('#connection_status_sub').text("");
		$('#status_icon').css('display', 'none');
		$('#status_ok_icon').css('display', 'none');
		$('#status_error_icon').css('display', 'none');
		$('#retry-button').css("display", "none");
	});

	$('#connect-form').submit(function(ev){
		ev.preventDefault();

		$('.before-submit').hide();
		$('#retry-button').css("display", "none");
		$('#submit-message').removeClass('hidden');
		$('#connection_status').text('Bitte warten...');
		$('#connection_status_sub').text("");
		$('#status_icon').css('display', 'block');
		$('#status_ok_icon').css('display', 'none');
		$('#status_error_icon').css('display', 'none');

		$.post('/connect', $('#connect-form').serialize(), function(data){}).fail(function() {
			$('#retry-button').css("display", "block");
			$('#status_icon').css('display', 'none');
			$('#status_ok_icon').css('display', 'none');
			$('#status_error_icon').css('display', 'block');

			$('#connection_status').text('Fehler mit der Verbindung');
			$('#connection_status_sub').text('Bitte verbinde dich erneut mit dem Hotspot oder starte das micast-system erneut!');
			
		});

		global_timer = setInterval(function() {
			$.get('/connect_state', function(response) {

				var connection_response = JSON.parse(response);
				if (connection_response.connected === true) {

					clearInterval(global_timer);
					$('#status_icon').css('display', 'none');
					$('#status_ok_icon').css('display', 'block');
					$('#status_error_icon').css('display', 'none');

					$('#connection_status').text('Erfolgreich verbunden');
					$('#connection_status_sub').text('Sie können das System jetzt verwenden');
				} else {
					if (connection_response.error === true) {
						clearInterval(global_timer);
						$('#retry-button').css("display", "block");
						$('#status_icon').css('display', 'none');
						$('#status_ok_icon').css('display', 'none');
						$('#status_error_icon').css('display', 'block');

						$('#connection_status').text('Eine Verbindung konnte nicht hergestellt werden');
						$('#connection_status_sub').text(connection_response.status);
					}
				}
			}).fail(function() {
				$('#retry-button').css("display", "block");
				$('#status_icon').css('display', 'none');
				$('#status_ok_icon').css('display', 'none');
				$('#status_error_icon').css('display', 'block');

				$('#connection_status').text('Fehler mit der Verbindung');
				$('#connection_status_sub').text('Bitte verbinde dich erneut mit dem Hotspot oder starte das micast-system erneut!');
				
			});
		}, 200);
	
	});
});
