'use strict';

// Hashes a file in 4 KiB slices. After each slice the hasher state is saved with getState(),
// the digest of the data so far is shown, and the state is restored with setState().
var sliceSize = 4096;

var fileElement = document.getElementById('file');
fileElement.addEventListener('change', function (e) {
  var file = e.target.files[0];
  var hasher = CryptoApi.getHasher('sha256');
  var fReader = new FileReader();
  var i = 0;
  var progress = document.getElementById('hash-progress');

  fReader.onloadend = function (evt) {
    if (evt.target.readyState === FileReader.DONE) {
      hasher.update(evt.target.result);
      var state = hasher.getState();
      document.getElementById('hash').textContent = CryptoApi.encoder.toHex(hasher.finalize());

      var percent = (Math.round(1000 * Math.min(i + sliceSize, file.size) / file.size) / 10).toString();
      progress.setAttribute('aria-valuenow', percent);
      progress.style.width = percent + '%';
      progress.textContent = percent + '%';
      hasher.setState(state);
      if (i < file.size) {
        i += sliceSize;
        var blob = file.slice(i, Math.min(i + sliceSize, file.size));
        fReader.readAsBinaryString(blob);
      }
    }
  };
  var blob = file.slice(i, Math.min(i + sliceSize, file.size));
  fReader.readAsBinaryString(blob);
});
