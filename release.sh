#!/bin/bash

smoke_test()
{
  cfg="$2"
  cfg_binaries='"Boot": "output/platform/pc/boot/boot.img", "Kernel": "output/platform/pc/bin/kernel.img"'
  image_name='webg-smoke-test'
  instance_name="$image_name-`date +'%s'`"
  tmp_file=output/test/smoke.json
  server_port=8080
  if [ -z $cfg ]; then # no provider-specific cloud configuration has ben supplied
    cfg=${OPS_CONF}    # use generic cloud configuration, if supplied
  fi
  if [ ! -z "$cfg" ]; then
    if [ ! -f "$cfg" ]; then
      echo Configuration file "$cfg" not found, aborting "$1" smoke test
      return 1
    fi
    # Add bootloader and kernel files from this build to the user-supplied configuration
    cfg=`cat "$cfg"`
    cfg=${cfg%'}'}', '"$cfg_binaries"'}'
    echo "$cfg" > $tmp_file
  else
    echo '{'"$cfg_binaries"'}' > $tmp_file
  fi
  cfg='-c '"$tmp_file"
  res=0
  echo 'Creating '"$1"' image '"$image_name"
  ops image create -t "$1" output/test/runtime/bin/webg -i "$image_name" "$cfg"
  if [ ! "$?" = "0" ]; then
    echo "$1"' image creation failed'
    if [ -z "$2" ]; then
      echo 'Use can use the '"$3"' environment variable to specify a config.json file specific for '"$1"','
      echo 'or OPS_CONF for a config.json file valid for all cloud providers'
    fi
    res=1
  else
    echo 'Creating '"$1"' instance '"$instance_name"
    ops instance create -t "$1" "$image_name" -i "$instance_name" "$cfg" -p "$server_port"
    if [ ! "$?" = "0" ]; then
      echo "$1"' instance creation failed'
      res=1
    else
      while true; do
        instance_list=`ops instance list -t "$1" "$cfg"`
        instance_rows=`echo "$instance_list" | grep "$instance_name"`
        instance_row=`echo "$instance_rows" | grep -i running`
        if [ "$?" = "0" ]; then
          break
        else
          echo 'Waiting for instance to run...'
          sleep 10
        fi
      done
      list_header=`echo "$instance_list" | grep "PUBLIC IP"`
      list_header=${list_header%*PUBLIC IP*}
      separator_count=`echo "${list_header}" | awk -F'|' '{print NF-1}'`
      # remove all characters up to the first $separator_count separators
      # (i.e. remove any columns before public IP)
      for i in `seq 1 $separator_count`
      do
        instance_row=${instance_row#*|}
      done
      # remove any columns after public IP
      instance_ip=${instance_row%%|*}
      # trim whitespace
      instance_ip=`echo ${instance_ip##|*} | xargs`
      ab -c 100 -n 1000 -dq http://"$instance_ip":"$server_port"/
      if [ ! "$?" = "0" ]; then
        echo "$1"' web server test failed'
        res=2
      fi
      ops instance delete -t "$1" "$instance_name" "$cfg"
    fi
    ops image delete --assume-yes -t "$1" "$image_name" "$cfg"
  fi
  rm $tmp_file
  return $res
}

if [ "$#" -ge 1 ]; then
if [ "$1" = 'smoke-test' ]; then
  make target || exit 2
  smoke_test "gcp" "${OPS_CONF_GCP}" "OPS_CONF_GCP" || exit 2
  smoke_test "aws" "${OPS_CONF_AWS}" "OPS_CONF_AWS" || exit 2
  echo Smoke tests completed successfully
else
  echo Unknown command "$1"
  exit 1
fi
fi

version=0.1.41
plat="$(uname -s | awk '{print tolower($0)}')"

tgz="nanos-release-$plat-$version.tar.gz"
hash="nanos-release-$plat-$version.md5"

rm "$tgz"
rm "$hash"

version="$version" make release

gsutil cp release/"$tgz" gs://nanos/release/"$version"/"$tgz"
gsutil setacl public-read gs://nanos/release/"$version"/"$tgz"

if [ "$plat" = 'darwin' ]
then
  md5 -q release/"$tgz" > "$hash"
else
  md5sum release/"$tgz" | awk '{print $1}' > "$hash"
fi

gsutil cp "$hash" gs://nanos/release/"$version"/"$hash"
gsutil setacl public-read gs://nanos/release/"$version"/"$hash"

echo "$version" > latest.txt
gsutil cp latest.txt gs://nanos/release/latest.txt
gsutil setacl public-read gs://nanos/release/latest.txt
