```
/script install buffers.pl
/script install input_lock.rb
```

Wait for scripts to install asynchronously, then:

```
/set weechat.look.buffer_time_format "%H:%M:%S"
/set weechat.look.separator_horizontal "~"
/set weechat.bar.nicklist.position top
/set weechat.bar.nicklist.size 2
/set weechat.color.chat_time gray
/set weechat.bar.status.color_bg black
/set weechat.color.chat_nick_self *!lightgreen
/set weechat.bar.buffers.size 20
/set weechat.bar.status.hidden off
/set weechat.bar.status.color_bg darkgray
/set weechat.bar.status.items “buffer_number+:+buffer_name+{buffer_nicklist_count}+buffer_filter,completion,scroll”
/set weechat.bar.input.size 0
/set weechat.bar.input.size_max 3

/set irc.look.smart_filter on
/filter add irc_smart * irc_smart_filter *
/set weechat.color.chat_nick_colors red,green,brown,blue,magenta,cyan,white,lightred,lightgreen,yellow,lightblue,lightmagenta,lightcyan

/set irc.server_default.away_check 5
/set irc.server_default.away_check_max_nicks 25

/set weechat.look.prefix_same_nick ↪

/set buffers.color.number white
/set buffers.look.hotlist_counter on
/set buffers.look.name_size_max 20
/set buffers.color.current_bg default
/set buffers.color.current_fg blue
/set buffers.color.hotlist_message_bg default
/set buffers.color.hotlist_message_fg yellow

/key bind meta-i /set plugins.var.ruby.input_lock.enabled off
/key bind meta-I /set plugins.var.ruby.input_lock.enabled on# http://zanshin.net/2015/01/10/a-guide-for-setting-up-weechat-and-bitlbee/
```

Add some servers and channels:
```
/server add freenode chat.freenode.net
/set irc.server.freenode.autoconnect on
/set irc.server.freenode.nicks "relgar,ceran"
/set irc.server.freenode.addresses "chat.freenode.net/7000"
/set irc.server.freenode.ssl on
/set irc.server.freenode.sasl_username "relgar"
/set irc.server.freenode.sasl_password "xxxxxxx"
```
