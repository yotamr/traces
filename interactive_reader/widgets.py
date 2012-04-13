import urwid

class AnsiText(urwid.Text):
    foregrounds = {'30' : 'black',
                   '31' : 'light red',
                   '32' : 'light green',
                   '33' : 'yellow',
                   '34' : 'light blue',
                   '35' : 'light magenta',
                   '36' : 'light cyan',
                   '37' : 'white',
                   '39' : 'default'
                   }
    
    attributes = {'1' : 'bold',
                  '0' : ''}
                  
    backgrounds = {
        '40' : 'black',
        '41' : 'light red',
        '42' : 'light green',
        '43' : 'yellow',
        '44' : 'light blue',
        '45' : 'light magenta',
        '46' : 'light cyan',
        '47' : 'white',
        '49' : 'default'    
        }

    def __init__(self, text, *args, **kw):
        if isinstance(text, str):
            text = self._ansi_to_urwid_markup(text)
            
        super(AnsiText, self).__init__(text, *args, **kw)

    def _ansi_attributes_to_markup(self, attributes):
        split_attrs = attributes.split(';')
        markup = ["", "", "default"]
        dicts_to_indexes = ((self.attributes, 0),
                            (self.foregrounds, 1),
                            (self.backgrounds, 2))
        for attr in split_attrs:
            for attr_dict, index in dicts_to_indexes:
                if attr in attr_dict:
                    markup[index] = attr_dict[attr]

        return '_'.join(markup)
    
    def _ansi_to_urwid_markup(self, text):
        markup = []
        ansi_elements = text.split('\033[')
        if len(ansi_elements) == 1:
            return text

        markup.append(ansi_elements[0])
        for ansi_element in ansi_elements[1:]:
            split_attrs = ansi_element.split('m')
            attributes = split_attrs[0]
            raw_text = 'm'.join(split_attrs[1:])
            if not raw_text:
                continue
            markup.append((self._ansi_attributes_to_markup(attributes), raw_text))

        return markup
    
    @classmethod
    def get_palette(cls, *args, **kw):
        palette = []
        palette.extend([('_'.join((attribute, foreground, background)), foreground, background, attribute)
                        for attribute in cls.attributes.values()
                        for foreground in cls.foregrounds.values()
                        for background in cls.backgrounds.values()])

        return palette
    
    
class AdvancedEdit(urwid.Edit):
    def __init__(self, completer = None, edit_text=u'',
                 history=None, **kwargs):
        if not history:
            history = []
        self.completer = completer
        self.history = list(history)  # we temporarily add stuff here
        self.historypos = None

        if not isinstance(edit_text, unicode):
            edit_text = string_decode(edit_text)
        self.start_completion_pos = len(edit_text)
        self.completions = None
        urwid.Edit.__init__(self, edit_text=edit_text, **kwargs)

    def set_completer(self, completer):
        self.completer = completer
        
    def keypress(self, size, key):
        # if we tabcomplete
        if key in ['tab', 'shift tab'] and self.completer:
            # if not already in completion mode
            if not self.completions:
                self.completions = [(self.edit_text, self.edit_pos)] + \
                    self.completer.complete(self.edit_text, self.edit_pos)
                self.focus_in_clist = 1
            else:  # otherwise tab through results
                if key == 'tab':
                    self.focus_in_clist += 1
                else:
                    self.focus_in_clist -= 1
            if len(self.completions) > 1:
                ctext, cpos = self.completions[self.focus_in_clist %
                                          len(self.completions)]
                self.set_edit_text(ctext)
                self.set_edit_pos(cpos)
            else:
                self.edit_pos += 1
                if self.edit_pos >= len(self.edit_text):
                    self.edit_text += ' '
                self.completions = None
        elif key in ['up', 'down']:
            if self.history:
                if self.historypos == None:
                    self.history.append(self.edit_text)
                    self.historypos = len(self.history) - 1
                if key == 'cursor up':
                    self.historypos = (self.historypos + 1) % len(self.history)
                else:
                    self.historypos = (self.historypos - 1) % len(self.history)
                self.set_edit_text(self.history[self.historypos])
        else:
            result = urwid.Edit.keypress(self, size, key)
            self.completions = None
            return result
                
