import sys
import signal
import operator
import time
import urwid
from widgets import AnsiText, AdvancedEdit, AlwaysOnTopListBox
from completers import StringlistCompleter, MultipleSelectionCompleter
from _CTraceParser import TraceParser, TraceFilter, FilterParseError
from datetime import datetime

SECOND = 1000000000
MINUTE = SECOND * 60
HOUR = MINUTE * 60
DAY = HOUR * 24
YEAR = DAY * 365

__version__ = '0.1'

class TraceWalker(urwid.ListWalker):
    def __init__(self):
        self._reset()

    def _reset(self):
        self._record_cache = {}
        self._current_trace_position = 0;
        self._focus = 0
        self._modified()

    def seek_to_pos(self, pos):
        self._parser.get_previous_n_records(abs(self._current_trace_position - pos) + 1)
        self._reset()
        
    def reread(self):
        self._reset()
    
    def set_parser(self, parser):
        self._parser = parser

    def _format_raw_record(self, record):
        if not record:
            return None
        else:
            return AnsiText(record, wrap = "clip")
        
    def _get_record_at_pos(self, pos):
        if pos in self._record_cache:
            if self._record_cache[pos][0]:
                return self._record_cache[pos][0], pos
            else:
                return None, None

        if self._current_trace_position > pos:
            records = [(self._format_raw_record(formatted_record), raw_record)
                       for formatted_record, raw_record in self._parser.get_previous_n_records(self._current_trace_position - pos)]
            for i, (formatted_record, raw_record) in enumerate(records):
                self._record_cache[self._current_trace_position - (i + 1)] = (formatted_record, raw_record)
            
            formatted_record = records[-1][0]
        elif self._current_trace_position < pos:
            records = [(self._format_raw_record(formatted_record), raw_record)
                       for formatted_record, raw_record in self._parser.get_next_n_records(pos - self._current_trace_position)]
            
            for i, (formatted_record, raw_record) in enumerate(records):
                self._record_cache[self._current_trace_position + i + 1] = (formatted_record, raw_record)

                
            formatted_record = records[0][0]
        else:
            formatted_record, raw_record = self._parser.get_next_n_records(1)[0]
            self._current_trace_position += 1
            formatted_record = self._format_raw_record(formatted_record)
            self._record_cache[pos] = (formatted_record, raw_record)
            

        if not formatted_record:
            return None, None
        else:
            self._current_trace_position = pos
            return formatted_record, pos
                                             
    def get_focus(self):
        record, pos = self._get_record_at_pos(self._focus)
        return urwid.AttrMap(record, 'reveal focus'), pos

    def set_focus(self, focus):
        self._focus = focus
        self._modified()
        
    def get_next(self, start_from):
        records = self._get_record_at_pos(start_from + 1)

        return records
    
    def get_prev(self, start_from):
        records = self._get_record_at_pos(start_from - 1)
        return records

    def get_raw_record_at_pos(self, pos):
        if pos in self._record_cache:
            return self._record_cache[pos][1]
        else:
            return None

    def get_raw_record_at_focus(self,):
            return self._record_cache[self._focus][1]

    def seek_to_time(self, ts):
        result = self._parser.seek_to_time(ts)
        if result:
            self._reset()
            
        return result

    def find_next_by_expression(self, matcher):
        found_record = self._parser.find_next_by_expression(matcher.filter)
        if found_record:
            self._reset()

        self._parser.get_previous_n_records(1)
        return found_record

    def find_previous_by_expression(self, matcher):
        found_record = self._parser.find_previous_by_expression(matcher.filter)
        if found_record:
            self._reset()
            
        return found_record

    def set_indent(self, set_indent = True):
        self._parser.set_indent(set_indent)

    def set_filter(self, filter_text):
        if filter_text:
            try:
                parsed_filter = TraceFilter.from_string(self._parser, filter_text)
            except FilterParseError:
                return False
        else:
            parsed_filter = TraceFilter.true()
                

        self._filter = parsed_filter.filter
        self._parser.set_filter(self._filter)
        self.reread()
        return True
    
    def seek_to_end(self):
        self._parser.seek_to_end()
        self.reread()

    def seek_to_start(self):
        result = self._parser.seek_to_start()
        self.reread()

    def get_matcher_from_string(self, string):
        try:
            parsed_filter = TraceFilter.from_string(self._parser, string)
        except FilterParseError:
            return None

        return parsed_filter

    def get_completion_names(self):
        return self._parser.get_completion_names()
        

palette = [
        ('body','black','default', ''),
        ('foot','light gray', 'black'),
        ('key','light cyan', 'black', 'underline'),
        ('title', 'white', 'black',),
    ]

class TraceReaderUI(object):
    _footer_text = [
        ('title', "Trace reader " + __version__), "  ",
        ]

    def __init__(self):
        self._trace_walker = TraceWalker()
        self._trace_view = AlwaysOnTopListBox(self._trace_walker)
        self._edit_line = AdvancedEdit()
        self._info_line = urwid.Text('')
        self._footer = AnsiText(self._footer_text)
        self._command_indicator = urwid.Text('')
        self._command_indicator_string = '--> '
        self._command_mode = None
        self._last_command = None
        self._last_filter = None
        self._debug_enabled = True
        self._show_field_names = False
        self._cancel_operation = False
        self._progress_notification_record_multiple = 0

        footer_columns = urwid.AttrMap(urwid.Columns([self._footer, self._info_line]), 'foot')
        wrapped_edit_line = urwid.Columns([('fixed', len(self._command_indicator_string), self._command_indicator), self._edit_line])
        footer = urwid.Pile([footer_columns, wrapped_edit_line])
                                      
        self._main_frame = urwid.Frame(urwid.AttrWrap(self._trace_view, 'body'), footer = footer)

    def _metadata_updated_handler(self):
        self._edit_line.set_completer(MultipleSelectionCompleter(StringlistCompleter(self._trace_walker.get_completion_names())))

    def _get_progress_line(self, records_processed, current_offset):
        if not self._command_mode:
            return None
        
        if 'forward' in self._command_mode or 'filter' in self._command_mode:
            end_offset = self._trace_parser.end_offset
        else:
            end_offset = 0;

        remaining_records_to_process = abs(current_offset - end_offset)
        remaining_percent = remaining_records_to_process / (self._trace_parser.end_offset / 100)
        return '%d%% remaining to process' % (remaining_percent,)
            
    def _parser_event_handler(self, event, **kw):
        if event == 'metadata_updated':
            self._metadata_updated_handler()
        if event == 'operation_in_progress':
            records_processed = kw['records_processed']
            current_offset = kw['current_offset']
            if records_processed >= self._next_redraw_record_count:
                progress_line = self._get_progress_line(records_processed, current_offset)
                if progress_line:
                    self._info_line.set_text(progress_line)
                self.loop.draw_screen()
                self._next_redraw_record_count += self._progress_notification_record_block_size

            if self._cancel_operation:
                self._trace_parser.cancel_ongoing_operation()
                self._cancel_operation = False
            
        if event == 'interrupted':
            self._cancel_operation = True
        
    def open_file(self, filename):
        self._trace_parser = TraceParser(filename, self._parser_event_handler)
        self._progress_notification_record_block_size = self._trace_parser.end_offset / 10
        self._next_redraw_record_count = self._progress_notification_record_block_size
        self._trace_parser.set_color(True)
        self._trace_parser.set_relative_ts(False)
        self._trace_parser.set_indent(True)
        self._trace_parser.set_show_field_names(False)
        self._trace_walker.set_parser(self._trace_parser)
        self._trace_walker.reread()
        self._footer.set_text(self._footer_text + ['    ', filename])
        self._edit_line.set_completer(MultipleSelectionCompleter(StringlistCompleter(self._trace_walker.get_completion_names())))

    def _clear_edit_line(self):
        self._edit_line.set_edit_text('')
        self._command_indicator.set_text('')

    def _dumb_search(self, search_string):
        i = 0
        _, pos = self._trace_walker.get_focus()
        if 'forward' in self._command_mode:
            walker = self._trace_walker.get_next
            op = operator.add
        else:
            walker = self._trace_walker.get_prev
            op = operator.sub
            
        while not self._cancel_operation:
            record, _ = walker(op(pos, i))
            i += 1
            if not record:
                return 'expression not found'

            record_text = record.get_text()[0]
            if record_text.find(str(search_string)) != -1:
                break


    def _set_info_line(self, text):
        self._info_line.set_text(text)

    def _goto_end_of_edit_line(self):
        self._edit_line.edit_pos = 5
        
    def _handle_search_expression(self, matcher):
        start_time = time.time()

        _, pos = self._trace_view.get_focus()
        if self._command_mode == 'search_forward':
            result = self._trace_walker.find_next_by_expression(matcher)
            self._trace_view.set_focus(0, 'above')
        else:
            self._trace_walker.get_prev(pos)
            result = self._trace_walker.find_previous_by_expression(matcher)
            self._trace_view.set_focus(0, 'below')


        
        end_time = time.time()
        search_time = end_time - start_time
        
        if result:
            result = 'search succeeded after %f seconds' % (search_time,)
        else:
            result = 'search failed after %f seconds' % (search_time,)

            
        return result
    
    def _handle_search_command_string(self, command_str):
        self._cancel_operation = False
        matcher = self._trace_walker.get_matcher_from_string(command_str)
        if command_str == 'focus':
            return self._trace_walker.get_focus()
        
        result = self._trace_walker.seek_to_time(command_str)
        if result:
            return result
        elif matcher:
            return self._handle_search_expression(matcher)
        else:
            return self._dumb_search(command_str)

    def _handle_filter_command_string(self, command_str):
        if self._last_filter == command_str:
            return 'filter unchanged '
        
        result = self._trace_walker.set_filter(command_str)
        self._last_filter = command_str
        if result:
            return 'Filter set'
        else:
            return 'Error setting filter'

    def _seek_to_top(self):
        self._trace_walker.seek_to_pos(self._trace_view.get_top_position())
        
    def _handle_command_string(self, command_str):
        self._last_command = (self._command_mode, command_str)
        self._next_redraw_record_count = self._progress_notification_record_block_size
        self._seek_to_top()

        if self._command_mode in ('search_backward', 'search_forward'):
            status = self._handle_search_command_string(command_str)
        elif self._command_mode == 'filter':
            status = self._handle_filter_command_string(command_str)

        if status:
            self._set_info_line(str(status))
        self._command_mode = None
        self._trace_view.set_focus_to_top_widget()


            
    def _handle_command(self):
        text = self._edit_line.get_edit_text().strip()
        self._clear_edit_line()
        self._handle_command_string(text)
        

    def _do_search_input(self, direction):
        self._main_frame.set_focus('footer')
        self._command_mode = 'search_' + direction
        self._command_indicator.set_text(self._command_indicator_string)

    def _do_filter(self, new_filter = False):
        self._main_frame.set_focus('footer')
        self._command_mode = 'filter'
        if not new_filter:
            self._goto_end_of_edit_line()
            if self._last_filter:
                self._edit_line.set_edit_text(self._last_filter)
            self._edit_line.keypress((100,), 'end')
            
        self._command_indicator.set_text(self._command_indicator_string)

    def _run_command(self, command_mode, command_str):
        self._command_mode = command_mode
        self._handle_command_string(command_str)

        
    def _repeat_last_command(self):
        if not self._last_command:
            return
        
        command_mode, command_str = self._last_command
        self._run_command(command_mode, command_str)

    def _search_leave(self):
        command_mode = 'search_forward'
        command_str = 'nesting == %d and tid == %d' % (self._trace_walker.get_raw_record_at_focus().nesting, self._trace_walker.get_raw_record_at_focus().tid)

        self._run_command(command_mode, command_str)

    def _search_caller(self, input):
        directions = {'c' : 'forward',
                      'C' : 'backward'}

        command_mode = 'search_' + directions[input]
        nesting = self._trace_walker.get_raw_record_at_focus().nesting - 1
            
        command_str = 'nesting == %d and tid == %d' % (nesting, self._trace_walker.get_raw_record_at_focus().tid)

        self._run_command(command_mode, command_str)

    def _search_error(self, input):
        directions = {'e' : 'forward',
                      'E' : 'backward'}

        command_mode = 'search_' + directions[input]
        command_str = 'severity == ERROR'
        self._run_command(command_mode, command_str)

    def _search_info(self, input):
        directions = {'i' : 'forward',
                      'I' : 'backward'}

        command_mode = 'search_' + directions[input]
        command_str = 'severity == INFO'
        self._run_command(command_mode, command_str)
        
    def _search_warn(self, input):
        directions = {'w' : 'forward',
                      'W' : 'backward'}

        command_mode = 'search_' + directions[input]
        command_str = 'severity == WARN'
        self._run_command(command_mode, command_str)

    def _search_debug(self, input):
        directions = {'d' : 'forward',
                      'D' : 'backward'}

        command_mode = 'search_' + directions[input]
        command_str = 'severity == DEBUG'
        self._run_command(command_mode, command_str)

    def _toggle_field_names(self):
        self._show_field_names = not self._show_field_names
        self._trace_parser.set_show_field_names(self._show_field_names)
        self._seek_to_top()
        
    def _handle_input(self, input):
        if input in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        if input in ('s', 'S'):
            if input == 's':
                self._do_search_input('forward')
            elif input == 'S':
                self._do_search_input('backward')
                
        if input in ('f',):
            self._do_filter(False)
        if input in ('F',):
            self._do_filter(True)
        if input in ('n', 'N'):
            self._repeat_last_command()
        if input in ('e', 'E'):
            self._search_error(input)
        if input in ('d', 'D'):
            self._search_debug(input)
        if input in ('w', 'W'):
            self._search_warn(input)
        if input in ('i', 'I'):
            self._search_info(input)
        if input in ('c', 'C'):
            self._search_caller(input)
        if input in ('l'):
            self._search_leave()
        if input in ('x'):
            self._toggle_field_names()

        if input == 'end':
            self._trace_walker.seek_to_end()
            self._trace_view.set_focus(0, 'above')

        if input == 'home':
            self._trace_walker.seek_to_start()
            self._trace_view.set_focus(0, 'below')
            
        if input == 'enter' and self._main_frame.get_focus() == 'footer':
            self._handle_command()
            self._main_frame.set_focus('body')

        self._trace_view.set_focus_to_top_widget()
        self._trace_view.set_focus_valign('top')


    def _cancel_pending_commands(self):
        if self._command_mode:
            self._cancel_operation = True
            self._set_info_line('Cancelled')
            self._clear_edit_line()

        self._main_frame.set_focus('body')
        
    def _handle_keyboard_interrupt(self):
        self._cancel_pending_commands()

    def _handle_sigint(self, signal, frame):
        self._handle_keyboard_interrupt()
        
    def run(self, filename):
        signal.signal(signal.SIGINT, self._handle_sigint)
        self.loop = urwid.MainLoop(self._main_frame, AnsiText.get_palette() + palette, handle_mouse = False, unhandled_input=self._handle_input)
        self.open_file(filename)
        self.loop.run()


def main():
    reader_ui = TraceReaderUI()
    reader_ui.run(sys.argv[1])

if __name__=="__main__":
    main()
