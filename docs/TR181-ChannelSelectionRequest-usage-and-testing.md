# TR-181 ChannelSelectionRequest usage and testing

## Summary

The TR-181 ChannelSelectionRequest handling in the EasyMesh control path was tightened to validate incoming requests more strictly before they are forwarded to the EM control document.

This update covers:

- parsing of Class.N and Channel.M entries using 1-based indexing
- validation of OpClass values for the target radio
- validation that requested channels belong to the requested OpClass
- validation that the OpClass band matches the radio band
- validation of preference values and incomplete channel entries

## Method format

The request method name is expected to follow this pattern:

```text
Device.WiFi.DataElements.Network.Device.<device>.Radio.<radio>.ChannelSelectionRequest()
```

The payload uses nested Class.N and Channel.M objects, for example:

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()"
  Class.1.OpClass uint32 81
  Class.1.Channel.1.Channel string 1,6,11
  Class.1.Channel.1.Preference uint32 14
```

Class.N.Channel.M.Channel is a TR-181 list of unsignedInt, carried as a comma-separated string. Every channel in a Channel.M row takes that row's Preference; channels that need a different preference go in another Channel.M row.

### Validation rules

The implementation now rejects requests when:

- Class indices are not valid positive integers starting at 1, or are not contiguous from 1
- Channel indices are not valid positive integers starting at 1, or are not contiguous from 1 within each Class.N
- OpClass is missing or invalid for the selected radio
- OpClass band does not match the radio band
- Channel is not a comma-separated list of channel numbers in 1..255 (empty list, empty item or trailing comma)
- A Class.N lists more than 64 channels in total
- Requested channels are not valid for the selected OpClass
- Preference values are invalid for the implementation range
- A preference is supplied without a matching channel entry
- An incomplete or malformed class payload is provided

## Representative positive and negative cases

### 2.4 GHz (Radio.1) - Positive

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 1,6,11 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 82 Class.1.Channel.1.Channel string 14 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 83 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 5 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 9 Class.1.Channel.3.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 84 Class.1.Channel.1.Channel string 5 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 9 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 13 Class.1.Channel.3.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14 Class.2.OpClass uint32 83 Class.2.Channel.1.Channel string 5 Class.2.Channel.1.Preference uint32 14 Class.3.OpClass uint32 84 Class.3.Channel.1.Channel string 9 Class.3.Channel.1.Preference uint32 14
```

### 2.4 GHz (Radio.1) - Negative

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 999 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 14 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 82 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 83 Class.1.Channel.1.Channel string 13 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 115 Class.1.Channel.1.Channel string 36 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 100 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 6 Class.1.Channel.1.Preference uint32 255

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 6 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 6 Class.1.Channel.2.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.1.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 6
```

### 5 GHz (Radio.2) - Positive

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 115 Class.1.Channel.1.Channel string 36,40,44,48 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 116 Class.1.Channel.1.Channel string 36 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 44 Class.1.Channel.2.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 118 Class.1.Channel.1.Channel string 52 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 56 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 60 Class.1.Channel.3.Preference uint32 14 Class.1.Channel.4.Channel string 64 Class.1.Channel.4.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 121 Class.1.Channel.1.Channel string 100 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 104 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 108 Class.1.Channel.3.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 124 Class.1.Channel.1.Channel string 149 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 153 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 157 Class.1.Channel.3.Preference uint32 14 Class.1.Channel.4.Channel string 161 Class.1.Channel.4.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 128 Class.1.Channel.1.Channel string 42 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 58 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 106 Class.1.Channel.3.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 129 Class.1.Channel.1.Channel string 50 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 114 Class.1.Channel.2.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 115 Class.1.Channel.1.Channel string 36 Class.1.Channel.1.Preference uint32 14 Class.2.OpClass uint32 118 Class.2.Channel.1.Channel string 52 Class.2.Channel.1.Preference uint32 14 Class.3.OpClass uint32 121 Class.3.Channel.1.Channel string 100 Class.3.Channel.1.Preference uint32 14 Class.4.OpClass uint32 124 Class.4.Channel.1.Channel string 149 Class.4.Channel.1.Preference uint32 14
```

### 5 GHz (Radio.2) - Negative

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 999 Class.1.Channel.1.Channel string 36 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 115 Class.1.Channel.1.Channel string 149 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 116 Class.1.Channel.1.Channel string 40 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 128 Class.1.Channel.1.Channel string 36 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 129 Class.1.Channel.1.Channel string 100 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.2.ChannelSelectionRequest()" Class.1.OpClass uint32 115 Class.1.Channel.1.Channel string 500 Class.1.Channel.1.Preference uint32 14
```

### 6 GHz (Radio.3) - Positive

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1,5,9,13 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 132 Class.1.Channel.1.Channel string 3 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 11 Class.1.Channel.2.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 133 Class.1.Channel.1.Channel string 7 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 23 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 39 Class.1.Channel.3.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 134 Class.1.Channel.1.Channel string 15 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 47 Class.1.Channel.2.Preference uint32 14 Class.1.Channel.3.Channel string 79 Class.1.Channel.3.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14 Class.2.OpClass uint32 132 Class.2.Channel.1.Channel string 3 Class.2.Channel.1.Preference uint32 14 Class.3.OpClass uint32 133 Class.3.Channel.1.Channel string 7 Class.3.Channel.1.Preference uint32 14 Class.4.OpClass uint32 134 Class.4.Channel.1.Channel string 15 Class.4.Channel.1.Preference uint32 14
```

### 6 GHz (Radio.3) - Negative

```text
method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 999 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 81 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 115 Class.1.Channel.1.Channel string 36 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 250 Class.1.Channel.1.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 255

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 1 Class.1.Channel.2.Preference uint32 14

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1

method_values "Device.WiFi.DataElements.Network.Device.2.Radio.3.ChannelSelectionRequest()" Class.1.OpClass uint32 131 Class.1.Channel.1.Channel string 1 Class.1.Channel.1.Preference uint32 14 Class.1.Channel.2.Channel string 999 Class.1.Channel.2.Preference uint32 14
```

## Testing done
The test suite exercises:

- valid 2.4 GHz requests
- valid 5 GHz requests
- valid 6 GHz requests
- invalid OpClass values
- invalid channel values
- invalid preference values
- malformed class/channel structure
- missing channel or missing OpClass entries

### Expected behavior

- Valid requests are accepted and converted into the EM control subdocument / JSON payload.
- Invalid requests return an input error instead of being processed.
- Logging clearly identifies whether the failure is due to invalid OpClass, channel membership, band mismatch, or malformed structure.

## Notes for usage

When sending new requests:

1. Use radio-specific OpClass values that match the target band.
2. Keep channel values within the allowed set for the selected OpClass.
3. Start Class and Channel indexes at 1.
4. Include a matching channel entry whenever a preference is provided.
5. Prefer a single Class entry per request for simple channel lists; multiple classes can be used when requesting multiple independent channel sets.
6. To determine which physical radio an index refers to, query the corresponding radio identifier using:

```text
get Device.WiFi.DataElements.Network.Device.2.Radio.1.ID
```

Use the returned ID value together with the radio index in the request path so the channel selection is applied to the intended radio.
