using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.SegmentRotationTechnique
{
    internal class SegmentRotationTechnique : ISegmentRotationTechnique
    {
        public string ShuffleSegments(string input, int segmentLength)
        {
            if (string.IsNullOrWhiteSpace(input) || segmentLength <= 0)
            {
                return string.Empty;
            }

            var cleaned = new string(input.Where(char.IsLetterOrDigit).ToArray());
            if (cleaned.Length == 0)
            {
                return string.Empty;
            }

            var segments = CreateSegments(cleaned, segmentLength);
            if (segments.Count == 0)
            {
                return string.Empty;
            }

            int rotation = CalculateRotation(cleaned);
            var rotated = RotateSegments(segments, rotation).ToList();
            string checksum = CalculateChecksum(rotated);

            return $"{string.Join("-", rotated)}#{checksum}";
        }

        private static IReadOnlyList<string> CreateSegments(string cleaned, int segmentLength)
        {
            var segments = new List<string>();

            for (int i = 0; i < cleaned.Length; i += segmentLength)
            {
                int remaining = Math.Min(segmentLength, cleaned.Length - i);
                string segment = cleaned.Substring(i, remaining);

                if (segment.Length < segmentLength)
                {
                    char pad = cleaned[(i + segment.Length - 1 + cleaned.Length) % cleaned.Length];
                    segment = segment.PadRight(segmentLength, pad);
                }

                segments.Add(segment);
            }

            return segments;
        }

        private static int CalculateRotation(string cleaned)
        {
            int sum = cleaned.Sum(static c => c);
            return sum % Math.Max(cleaned.Length, 1);
        }

        private static IEnumerable<string> RotateSegments(IReadOnlyList<string> segments, int rotation)
        {
            if (segments.Count == 0)
            {
                return Array.Empty<string>();
            }

            int shift = rotation % segments.Count;
            if (shift < 0)
            {
                shift += segments.Count;
            }

            return segments.Skip(shift).Concat(segments.Take(shift));
        }

        private static string CalculateChecksum(IEnumerable<string> segments)
        {
            int total = 0;
            int index = 1;

            foreach (string segment in segments)
            {
                foreach (char character in segment)
                {
                    total += character * index;
                }

                index++;
            }

            int mod = total % 997;
            return mod.ToString("X3", CultureInfo.InvariantCulture);
        }
    }
}
