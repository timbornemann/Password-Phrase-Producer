﻿using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques
{
    internal class TBV1WithErrors : Itbv
    {

        readonly string buchstaben = "uK9@bR]fVQ2!M4A>€c)X0a^Häe=,1§DköU#YxgÄl²3B_q&Zs$8nO*C.6d~P%tL5{hS<p7³vÜz}?EÖw(yN°r/J[Fo´i`Iü|W'j+;m-G:T";
        readonly string[] buchstaben2 = new string[] { "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",

                "u", "K", "9", "@", "b", "R", "]", "f", "V", "Q", "2", "!", "M", "4", "A", ">",
                "€", "c", ")", "X", "0", "a", "^", "H", "ä", "e", "=", ",", "1", "§", "D", "k", "ö", "U",
                "#", "Y", "x", "g", "Ä", "l", "²", "B", "_", "q", "&", "Z", "s", "$", "8", "n", "O", "*", "C", ".",
                "6", "d", "~", "P", "%", "t", "L", "5", "{", "h", "S", "<", "p", "7", "³", "v", "Ü", "z", "}", "?",
                "E", "Ö", "w", "(", "y", "N", "°", "r", "/", "J", "[", "F", "o", "´", "i", "`", "I", "ü", "|",
                "W", "'", "j", "+", ";", "m", "-", "G", ":", "T",
        		//Ganz oft wiederholen
        };

        public string GeneratePassword(string input, int multiplier, int subtractor, int adder)
        {
            char[] inputChars = input.ToCharArray();
            int[] transformedValues = new int[inputChars.Length];
            string encrypted = " ";

            for (int i = 0; i < inputChars.Length; i++)
            {
                transformedValues[i] = this.buchstaben.IndexOf(inputChars[i]);
                transformedValues[i] *= multiplier;
                transformedValues[i] -= subtractor;
                transformedValues[i] += adder;
                encrypted += this.buchstaben2[transformedValues[i]];
            }

            for (int i = 0; i < multiplier; i++)
            {
                encrypted += this.buchstaben2[multiplier + subtractor * i];
                encrypted += this.buchstaben2[adder * multiplier];
                encrypted += this.buchstaben2[subtractor * 4 + multiplier + 3];
            }

            string finalResult = "";
            char[] encryptedChars = encrypted.ToCharArray();
            string reversed = " ";

            for (int j = encrypted.Length - 1; j >= 0; j--)
            {
                reversed += encrypted[j];
            }

            char[] reversedChars = reversed.ToCharArray();

            for (int k = 0; k < encrypted.Length; k++)
            {
                finalResult += reversedChars[k];
                finalResult += encryptedChars[k];
                finalResult += this.buchstaben2[k];
                finalResult += this.buchstaben2[adder + 1];
            }

            string resultWithoutSpaces = finalResult.Replace(" ", "");
            return resultWithoutSpaces;
        }

        public string Decrypt(string finalResult, int multiplier, int subtractor, int adder)
        {

            int L = finalResult.Length / 4;
            char[] encryptedChars = new char[L];
            char[] reversedChars = new char[L];

            for (int k = 0; k < L; k++)
            {
                reversedChars[k] = finalResult[4 * k];
                encryptedChars[k] = finalResult[4 * k + 1];
            }

            string encrypted = new string(encryptedChars);
            string reversed = new string(reversedChars);

            encrypted = encrypted.TrimStart();

            int extraLength = 3 * multiplier;
            int mainEncryptedLength = encrypted.Length - extraLength;
            string mainEncrypted = encrypted.Substring(0, mainEncryptedLength);

            List<int> transformedValues = new List<int>();

            foreach (char encryptedChar in mainEncrypted)
            {
                int transformedValue = Array.IndexOf(buchstaben2, encryptedChar.ToString());
                if (transformedValue == -1)
                {
                    throw new Exception("Ungültiges verschlüsseltes Zeichen gefunden.");
                }
                transformedValues.Add(transformedValue);
            }

            char[] inputChars = new char[transformedValues.Count];

            for (int i = 0; i < transformedValues.Count; i++)
            {
                int transformedValue = transformedValues[i];
                int numerator = transformedValue + subtractor - adder;

                if (numerator % multiplier != 0)
                {
                    throw new Exception($"Ungültige Transformation an Position {i}.");
                }

                int originalIndex = numerator / multiplier;

                if (originalIndex < 0 || originalIndex >= buchstaben.Length)
                {
                    throw new Exception($"Ursprünglicher Index außerhalb des Bereichs an Position {i}.");
                }

                inputChars[i] = buchstaben[originalIndex];
            }

            string input = new string(inputChars);
            return input;
        }

    }
}
